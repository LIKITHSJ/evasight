"""Reproducible, CPU-only MLP baseline for the processed Evasight datasets.

The validation partition is used both for early stopping and, after selecting
the best epoch, for isotonic calibration to match the existing XGBoost protocol.
The test partition is evaluated only after model selection and calibration.
"""
from __future__ import annotations

import argparse
import copy
import random
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import torch
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score, roc_curve
from sklearn.preprocessing import StandardScaler
from torch import Tensor, nn
from torch.nn import functional as F

from evasight.models.gbdt import EXCLUDE

DATASETS: dict[str, tuple[Path, str]] = {
    "cic2017": (Path("data/processed/cic_ids2017_improved"), "cic2017_improved"),
    "cic2018": (Path("data/processed/cic_ids2018_improved"), "cic2018_improved"),
    "unsw": (Path("data/processed/unsw_nb15"), "unsw"),
}
CATEGORICAL_FEATURES = ("proto", "service", "state")
DEFAULT_ARTIFACT_DIR = Path("artifacts")


@dataclass(frozen=True)
class TrainingConfig:
    """CPU training settings for the MLP baseline."""

    learning_rate: float = 0.001
    batch_size: int = 4096
    max_epochs: int = 50
    patience: int = 5
    seed: int = 42
    num_threads: int = 4
    shuffle_buffer_size: int = 65_536
    dropout: float = 0.2

    def __post_init__(self) -> None:
        if self.learning_rate <= 0:
            raise ValueError("learning_rate must be positive")
        if self.batch_size < 1:
            raise ValueError("batch_size must be at least 1")
        if self.max_epochs < 1:
            raise ValueError("max_epochs must be at least 1")
        if self.patience < 1:
            raise ValueError("patience must be at least 1")
        if self.num_threads < 1:
            raise ValueError("num_threads must be at least 1")
        if self.shuffle_buffer_size < 1:
            raise ValueError("shuffle_buffer_size must be at least 1")
        if not 0 <= self.dropout < 1:
            raise ValueError("dropout must be in [0, 1)")


def embedding_dimension(cardinality: int) -> int:
    """Return a deterministic embedding width: round(sqrt(cardinality)), clamped to [2, 50]."""
    if cardinality < 1:
        raise ValueError("categorical cardinality must be at least 1")
    return min(50, max(2, round(cardinality**0.5)))


class MLP(nn.Module):
    """Binary MLP with optional per-column categorical embeddings."""

    def __init__(
        self,
        numeric_features: int,
        categorical_cardinalities: Mapping[str, int] | None = None,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        if numeric_features < 0:
            raise ValueError("numeric_features cannot be negative")
        if not 0 <= dropout < 1:
            raise ValueError("dropout must be in [0, 1)")
        cardinalities = dict(categorical_cardinalities or {})
        if numeric_features == 0 and not cardinalities:
            raise ValueError("the model requires at least one input feature")
        if any(value < 1 for value in cardinalities.values()):
            raise ValueError("categorical cardinalities must be at least 1")

        self.numeric_features = numeric_features
        self.categorical_columns = tuple(cardinalities)
        self.embedding_dims = tuple(embedding_dimension(n) for n in cardinalities.values())
        self.embeddings = nn.ModuleList(
            nn.Embedding(cardinality + 1, dimension, padding_idx=0)
            for cardinality, dimension in zip(cardinalities.values(), self.embedding_dims)
        )
        input_features = numeric_features + sum(self.embedding_dims)
        self.network = nn.Sequential(
            nn.Linear(input_features, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
        )

    def forward(self, numerical: Tensor, categorical: Tensor | None = None) -> Tensor:
        """Return one unnormalized binary-classification logit per row."""
        if numerical.ndim != 2 or numerical.shape[1] != self.numeric_features:
            raise ValueError(
                f"numerical input must have shape (batch, {self.numeric_features})"
            )
        pieces = [numerical]
        if self.embeddings:
            if categorical is None:
                raise ValueError("categorical input is required by this model")
            if categorical.ndim != 2 or categorical.shape != (
                numerical.shape[0],
                len(self.embeddings),
            ):
                raise ValueError(
                    f"categorical input must have shape "
                    f"(batch, {len(self.embeddings)})"
                )
            pieces.extend(
                embedding(categorical[:, index].long())
                for index, embedding in enumerate(self.embeddings)
            )
        elif categorical is not None and (
            categorical.ndim != 2
            or categorical.shape[0] != numerical.shape[0]
            or categorical.shape[1] != 0
        ):
            raise ValueError("categorical input supplied to a numerical-only model")
        return self.network(torch.cat(pieces, dim=1))


def seed_everything(seed: int, num_threads: int = 4) -> None:
    """Seed Python, NumPy, and PyTorch and configure deterministic CPU execution."""
    if num_threads < 1:
        raise ValueError("num_threads must be at least 1")
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.set_num_threads(num_threads)
    torch.use_deterministic_algorithms(True)


def validate_numerical_features(values: np.ndarray, split_name: str = "input") -> None:
    """Reject numerical model inputs containing NaN or infinity."""
    if not np.isfinite(values).all():
        raise ValueError(f"{split_name} numerical features contain NaN or infinity")


def _category_key(value: Any) -> str | None:
    if pd.isna(value):
        return None
    return str(value)


def build_category_vocabularies(
    train: pd.DataFrame, columns: Sequence[str] = CATEGORICAL_FEATURES
) -> dict[str, dict[str, int]]:
    """Build sorted category-to-index vocabularies from training rows only.

    Index zero is reserved for unknown or missing categories; learned categories
    start at one.
    """
    vocabularies: dict[str, dict[str, int]] = {}
    for column in columns:
        if column not in train.columns:
            raise ValueError(f"training data is missing categorical feature {column!r}")
        values = {
            key
            for value in train[column].to_numpy()
            if (key := _category_key(value)) is not None
        }
        vocabularies[column] = {
            value: index for index, value in enumerate(sorted(values), start=1)
        }
    return vocabularies


def encode_categorical(
    frame: pd.DataFrame,
    vocabularies: Mapping[str, Mapping[str, int]],
) -> np.ndarray:
    """Encode categorical columns, mapping unseen and missing values to index zero."""
    encoded = np.zeros((len(frame), len(vocabularies)), dtype=np.int64)
    for index, (column, vocabulary) in enumerate(vocabularies.items()):
        if column not in frame.columns:
            raise ValueError(f"data is missing categorical feature {column!r}")
        encoded[:, index] = np.fromiter(
            (vocabulary.get(key, 0) if key is not None else 0
             for key in (_category_key(value) for value in frame[column].to_numpy())),
            dtype=np.int64,
            count=len(frame),
        )
    return encoded


def fit_numeric_scaler(
    train: pd.DataFrame, feature_names: Sequence[str]
) -> StandardScaler:
    """Fit a StandardScaler on training rows only after checking finiteness."""
    if not feature_names:
        raise ValueError("at least one numerical feature is required")
    try:
        values = train.loc[:, list(feature_names)].to_numpy(dtype=np.float32)
    except (TypeError, ValueError) as exc:
        raise ValueError("numerical features must contain numeric values") from exc
    validate_numerical_features(values, "training")
    return StandardScaler().fit(values)


def _iter_frames(
    parquet_path: Path, columns: Sequence[str], batch_size: int
) -> Iterator[pd.DataFrame]:
    parquet = pq.ParquetFile(parquet_path)
    present = set(parquet.schema_arrow.names)
    missing = [column for column in columns if column not in present]
    if missing:
        raise ValueError(f"{parquet_path} is missing required columns: {missing}")
    for record_batch in parquet.iter_batches(
        batch_size=batch_size, columns=list(columns), use_threads=False
    ):
        yield record_batch.to_pandas()


def _discover_training_features(
    train_path: Path, dataset: str, batch_size: int
) -> tuple[list[str], list[str], dict[str, dict[str, int]]]:
    """Apply the GBDT exclusion/constant-column rule in bounded training batches."""
    parquet = pq.ParquetFile(train_path)
    categorical = list(CATEGORICAL_FEATURES) if dataset == "unsw" else []
    missing_categorical = [
        name for name in categorical if name not in parquet.schema_arrow.names
    ]
    if missing_categorical:
        raise ValueError(
            f"UNSW training data is missing categorical features: {missing_categorical}"
        )
    candidates = [name for name in parquet.schema_arrow.names if name not in EXCLUDE]
    if not candidates:
        raise ValueError("no candidate model features remain after applying EXCLUDE")

    first_values: dict[str, Any] = {}
    variable: set[str] = set()
    category_values: dict[str, set[str]] = {name: set() for name in categorical}
    for frame in _iter_frames(train_path, candidates, batch_size):
        for column in candidates:
            series = frame[column]
            if column in category_values:
                category_values[column].update(
                    key for value in series.to_numpy()
                    if (key := _category_key(value)) is not None
                )
                continue
            if not pd.api.types.is_numeric_dtype(series.dtype):
                raise ValueError(
                    f"non-numerical model feature {column!r}; only UNSW's "
                    f"{CATEGORICAL_FEATURES} may be categorical"
                )
            values = series.dropna()
            if values.empty:
                continue
            first = first_values.setdefault(column, values.iloc[0])
            if column not in variable and not values.eq(first).all():
                variable.add(column)

    selected = [
        column
        for column in candidates
        if (
            len(category_values[column]) > 1
            if column in category_values
            else column in variable
        )
    ]
    if not selected:
        raise ValueError("no non-constant model features remain in the training partition")
    selected_categorical = [column for column in categorical if column in selected]
    numeric = [column for column in selected if column not in selected_categorical]
    if not numeric and not selected_categorical:
        raise ValueError("no usable model features remain")
    vocabularies = {
        column: {
            value: index for index, value in enumerate(sorted(category_values[column]), start=1)
        }
        for column in selected_categorical
    }
    return selected, numeric, vocabularies


def _fit_streaming_scaler(
    train_path: Path, numeric_features: Sequence[str], batch_size: int
) -> StandardScaler | None:
    if not numeric_features:
        return None
    scaler = StandardScaler()
    for frame in _iter_frames(train_path, numeric_features, batch_size):
        try:
            values = frame.to_numpy(dtype=np.float32)
        except (TypeError, ValueError) as exc:
            raise ValueError("training numerical features must contain numeric values") from exc
        validate_numerical_features(values, "training")
        scaler.partial_fit(values)
    return scaler


def _transform_numeric(
    frame: pd.DataFrame,
    feature_names: Sequence[str],
    scaler: StandardScaler | None,
    split_name: str,
) -> np.ndarray:
    if not feature_names:
        return np.empty((len(frame), 0), dtype=np.float32)
    try:
        values = frame.loc[:, list(feature_names)].to_numpy(dtype=np.float32)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{split_name} numerical features must contain numeric values") from exc
    validate_numerical_features(values, split_name)
    if scaler is not None:
        values = scaler.transform(values)
    return np.asarray(values, dtype=np.float32, order="C")


def _predict_partition(
    model: MLP,
    path: Path,
    feature_names: Sequence[str],
    numeric_features: Sequence[str],
    scaler: StandardScaler | None,
    vocabularies: Mapping[str, Mapping[str, int]],
    batch_size: int,
    include_attack_categories: bool = False,
) -> tuple[np.ndarray, np.ndarray, np.ndarray | None]:
    columns = list(dict.fromkeys(
        [*feature_names, "label"]
        + (["attack_cat"] if include_attack_categories else [])
    ))
    probabilities: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    attack_categories: list[np.ndarray] = []
    model.eval()
    with torch.inference_mode():
        for frame in _iter_frames(path, columns, batch_size):
            numerical = _transform_numeric(frame, numeric_features, scaler, path.stem)
            categorical = encode_categorical(frame, vocabularies) if vocabularies else None
            logits = model(
                torch.from_numpy(numerical),
                torch.from_numpy(categorical) if categorical is not None else None,
            )
            probabilities.append(torch.sigmoid(logits).squeeze(1).numpy())
            labels.append(frame["label"].to_numpy(dtype=np.int64))
            if include_attack_categories and "attack_cat" in frame:
                attack_categories.append(frame["attack_cat"].astype(str).to_numpy())
    if not probabilities:
        raise ValueError(f"{path} contains no rows")
    categories = np.concatenate(attack_categories) if attack_categories else None
    return np.concatenate(probabilities), np.concatenate(labels), categories


def _validation_loss(
    model: MLP,
    path: Path,
    numeric_features: Sequence[str],
    scaler: StandardScaler | None,
    vocabularies: Mapping[str, Mapping[str, int]],
    batch_size: int,
) -> tuple[float, np.ndarray, np.ndarray]:
    columns = list(dict.fromkeys(
        [*numeric_features, *vocabularies.keys(), "label"]
    ))
    total_loss = 0.0
    total_rows = 0
    probabilities: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    model.eval()
    with torch.inference_mode():
        for frame in _iter_frames(path, columns, batch_size):
            numerical = _transform_numeric(frame, numeric_features, scaler, "validation")
            categorical = encode_categorical(frame, vocabularies) if vocabularies else None
            y = frame["label"].to_numpy(dtype=np.float32)
            logits = model(
                torch.from_numpy(numerical),
                torch.from_numpy(categorical) if categorical is not None else None,
            )
            total_loss += float(F.binary_cross_entropy_with_logits(
                logits.squeeze(1), torch.from_numpy(y), reduction="sum"
            ))
            total_rows += len(y)
            probabilities.append(torch.sigmoid(logits).squeeze(1).numpy())
            labels.append(y.astype(np.int64))
    if not total_rows:
        raise ValueError(f"{path} contains no rows")
    return total_loss / total_rows, np.concatenate(probabilities), np.concatenate(labels)


def _bounded_shuffle_batches(
    batches: Iterator[tuple[np.ndarray, np.ndarray | None, np.ndarray]],
    buffer_size: int,
    rng: np.random.Generator,
    output_batch_size: int,
) -> Iterator[tuple[np.ndarray, np.ndarray | None, np.ndarray]]:
    """Shuffle streamed aligned records through a fixed-size replacement buffer."""
    if buffer_size < 1:
        raise ValueError("buffer_size must be at least 1")
    if output_batch_size < 1:
        raise ValueError("output_batch_size must be at least 1")

    buffered: tuple[np.ndarray, np.ndarray | None, np.ndarray] | None = None
    output: tuple[np.ndarray, np.ndarray | None, np.ndarray] | None = None
    filled = 0
    output_filled = 0

    def allocate(
        values: tuple[np.ndarray, np.ndarray | None, np.ndarray], capacity: int
    ) -> tuple[np.ndarray, np.ndarray | None, np.ndarray]:
        numerical, categorical, labels = values
        if numerical.ndim != 2 or labels.ndim != 1:
            raise ValueError("numerical batches must be 2D and labels must be 1D")
        if len(numerical) != len(labels):
            raise ValueError("numerical features and labels must have equal row counts")
        if categorical is not None and (
            categorical.ndim != 2
            or len(categorical) != len(labels)
        ):
            raise ValueError("categorical features and labels must have equal row counts")
        return (
            np.empty((capacity, *numerical.shape[1:]), dtype=numerical.dtype),
            None
            if categorical is None
            else np.empty((capacity, *categorical.shape[1:]), dtype=categorical.dtype),
            np.empty(capacity, dtype=labels.dtype),
        )

    def allocate_output(
        values: tuple[np.ndarray, np.ndarray | None, np.ndarray], capacity: int
    ) -> tuple[np.ndarray, np.ndarray | None, np.ndarray]:
        numerical, categorical, labels = values
        return (
            np.empty((capacity, *numerical.shape[1:]), dtype=numerical.dtype),
            None
            if categorical is None
            else np.empty((capacity, *categorical.shape[1:]), dtype=categorical.dtype),
            np.empty(capacity, dtype=labels.dtype),
        )

    def copy_record(
        target: tuple[np.ndarray, np.ndarray | None, np.ndarray],
        target_index: int,
        source: tuple[np.ndarray, np.ndarray | None, np.ndarray],
        source_index: int,
    ) -> None:
        target[0][target_index] = source[0][source_index]
        if target[1] is not None and source[1] is not None:
            target[1][target_index] = source[1][source_index]
        target[2][target_index] = source[2][source_index]

    for batch in batches:
        numerical, categorical, labels = batch
        if len(numerical) == 0:
            continue
        if buffered is None:
            buffered = allocate(batch, buffer_size)
            output = allocate_output(batch, output_batch_size)
        if (
            numerical.ndim != 2
            or labels.ndim != 1
            or len(numerical) != len(labels)
            or (
                categorical is not None
                and (categorical.ndim != 2 or len(categorical) != len(labels))
            )
        ):
            raise ValueError(
                "each streamed batch must contain aligned numerical, "
                "categorical, and label rows"
            )
        if (buffered[1] is None) != (categorical is None):
            raise ValueError("categorical inputs must be consistently present or absent")
        if numerical.shape[1:] != buffered[0].shape[1:] or labels.dtype != buffered[2].dtype:
            raise ValueError("streamed batches must have consistent feature shapes and dtypes")
        if categorical is not None and (
            categorical.shape[1:] != buffered[1].shape[1:]
            or categorical.dtype != buffered[1].dtype
        ):
            raise ValueError("streamed categorical batches must have consistent shapes and dtypes")

        offset = 0
        if filled < buffer_size:
            count = min(buffer_size - filled, len(labels))
            buffered[0][filled : filled + count] = numerical[:count]
            if categorical is not None:
                buffered[1][filled : filled + count] = categorical[:count]
            buffered[2][filled : filled + count] = labels[:count]
            filled += count
            offset = count

        for row in range(offset, len(labels)):
            buffer_index = int(rng.integers(buffer_size))
            copy_record(output, output_filled, buffered, buffer_index)
            copy_record(buffered, buffer_index, batch, row)
            output_filled += 1
            if output_filled == output_batch_size:
                yield (
                    output[0].copy(),
                    None if output[1] is None else output[1].copy(),
                    output[2].copy(),
                )
                output_filled = 0

    if buffered is None or output is None:
        return
    for buffer_index in rng.permutation(filled):
        copy_record(output, output_filled, buffered, int(buffer_index))
        output_filled += 1
        if output_filled == output_batch_size:
            yield (
                output[0].copy(),
                None if output[1] is None else output[1].copy(),
                output[2].copy(),
            )
            output_filled = 0
    if output_filled:
        yield (
            output[0][:output_filled].copy(),
            None if output[1] is None else output[1][:output_filled].copy(),
            output[2][:output_filled].copy(),
        )


def _train_epoch(
    model: MLP,
    optimizer: torch.optim.Optimizer,
    path: Path,
    numeric_features: Sequence[str],
    scaler: StandardScaler | None,
    vocabularies: Mapping[str, Mapping[str, int]],
    config: TrainingConfig,
    epoch: int,
) -> float:
    columns = list(dict.fromkeys(
        [*numeric_features, *vocabularies.keys(), "label"]
    ))
    rng = np.random.default_rng(config.seed + epoch)
    total_loss = 0.0
    total_rows = 0
    model.train()
    batches = (
        (
            _transform_numeric(frame, numeric_features, scaler, "training"),
            encode_categorical(frame, vocabularies) if vocabularies else None,
            frame["label"].to_numpy(dtype=np.float32),
        )
        for frame in _iter_frames(path, columns, config.batch_size)
    )
    shuffled_batches = _bounded_shuffle_batches(
        batches, config.shuffle_buffer_size, rng, config.batch_size
    )
    for numerical, categorical, y in shuffled_batches:
        x_num = torch.from_numpy(numerical)
        x_cat = torch.from_numpy(categorical) if categorical is not None else None
        target = torch.from_numpy(y)
        optimizer.zero_grad(set_to_none=True)
        logits = model(x_num, x_cat).squeeze(1)
        loss = F.binary_cross_entropy_with_logits(logits, target)
        loss.backward()
        optimizer.step()
        total_loss += float(loss.detach()) * len(y)
        total_rows += len(y)
    if not total_rows:
        raise ValueError(f"{path} contains no rows")
    return total_loss / total_rows


def expected_calibration_error(y: np.ndarray, probabilities: np.ndarray, bins: int = 15) -> float:
    """Compute fixed-width ECE with the same binning convention as ``gbdt.py``."""
    if bins < 1:
        raise ValueError("bins must be at least 1")
    bin_ids = np.minimum((probabilities * bins).astype(int), bins - 1)
    return float(sum(
        (bin_ids == index).mean()
        * abs(y[bin_ids == index].mean() - probabilities[bin_ids == index].mean())
        for index in range(bins)
        if (bin_ids == index).any()
    ))


def _metrics(
    labels: np.ndarray,
    probabilities: np.ndarray,
    attack_categories: np.ndarray | None = None,
) -> dict[str, Any]:
    if np.unique(labels).size != 2:
        raise ValueError("evaluation partition must contain both binary label classes")
    false_positive_rate, true_positive_rate, _ = roc_curve(labels, probabilities)
    predicted = probabilities >= 0.5
    benign = labels == 0
    metrics: dict[str, Any] = {
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "pr_auc": float(average_precision_score(labels, probabilities)),
        "brier_score": float(brier_score_loss(labels, probabilities)),
        "ece": expected_calibration_error(labels, probabilities),
        "tpr_at_1pct_fpr": float(np.interp(0.01, false_positive_rate, true_positive_rate)),
        "benign_false_positive_rate_at_0_5": (
            float(predicted[benign].mean()) if benign.any() else float("nan")
        ),
    }
    if attack_categories is not None:
        categories = sorted(set(attack_categories) - {"BENIGN"})
        metrics["per_attack_category_recall_at_0_5"] = {
            category: float(predicted[attack_categories == category].mean())
            for category in categories
        }
    return metrics


def train_dataset(
    dataset: str = "cic2017",
    data_dir: Path | None = None,
    artifact_dir: Path = DEFAULT_ARTIFACT_DIR,
    config: TrainingConfig = TrainingConfig(),
) -> dict[str, Any]:
    """Train, calibrate, evaluate, and save one dataset-specific MLP baseline."""
    if dataset not in DATASETS:
        raise ValueError(f"unknown dataset {dataset!r}; expected one of {tuple(DATASETS)}")
    default_data, tag = DATASETS[dataset]
    partition_dir = data_dir or default_data
    train_path = partition_dir / "train.parquet"
    validation_path = partition_dir / "val.parquet"
    test_path = partition_dir / "test.parquet"
    for path in (train_path, validation_path, test_path):
        if not path.is_file():
            raise FileNotFoundError(f"required partition does not exist: {path}")

    seed_everything(config.seed, config.num_threads)
    selected_features, numeric_features, vocabularies = _discover_training_features(
        train_path, dataset, config.batch_size
    )
    categorical_features = list(vocabularies)
    scaler = _fit_streaming_scaler(train_path, numeric_features, config.batch_size)
    cardinalities = {name: len(vocabulary) for name, vocabulary in vocabularies.items()}
    model = MLP(len(numeric_features), cardinalities, config.dropout)
    optimizer = torch.optim.Adam(model.parameters(), lr=config.learning_rate)

    best_loss = float("inf")
    best_epoch = 0
    best_state: dict[str, Tensor] | None = None
    best_validation_probabilities: np.ndarray | None = None
    best_validation_labels: np.ndarray | None = None
    epochs_without_improvement = 0

    for epoch in range(1, config.max_epochs + 1):
        train_loss = _train_epoch(
            model, optimizer, train_path, numeric_features, scaler, vocabularies, config, epoch
        )
        validation_loss, validation_probabilities, validation_labels = _validation_loss(
            model, validation_path, numeric_features, scaler, vocabularies, config.batch_size
        )
        print(
            f"epoch {epoch:02d}/{config.max_epochs} "
            f"train_bce={train_loss:.6f} val_bce={validation_loss:.6f}"
        )
        if validation_loss < best_loss:
            best_loss = validation_loss
            best_epoch = epoch
            best_state = copy.deepcopy(model.state_dict())
            best_validation_probabilities = validation_probabilities
            best_validation_labels = validation_labels
            epochs_without_improvement = 0
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= config.patience:
                break

    if (
        best_state is None
        or best_validation_probabilities is None
        or best_validation_labels is None
    ):
        raise RuntimeError("training completed without selecting a best epoch")

    model.load_state_dict(best_state)
    calibrator = IsotonicRegression(out_of_bounds="clip").fit(
        best_validation_probabilities, best_validation_labels
    )
    raw_probabilities, test_labels, attack_categories = _predict_partition(
        model,
        test_path,
        selected_features,
        numeric_features,
        scaler,
        vocabularies,
        config.batch_size,
        include_attack_categories=True,
    )
    calibrated_probabilities = calibrator.predict(raw_probabilities)
    metrics = {
        "raw": _metrics(test_labels, raw_probabilities, attack_categories),
        "isotonic_calibrated": _metrics(
            test_labels, calibrated_probabilities, attack_categories
        ),
    }
    print(f"\nbest epoch: {best_epoch} | validation BCE: {best_loss:.6f}")
    for name, scores in metrics.items():
        print(
            f"{name}: ROC-AUC={scores['roc_auc']:.5f} "
            f"PR-AUC={scores['pr_auc']:.5f} "
            f"Brier={scores['brier_score']:.5f} ECE={scores['ece']:.5f} "
            f"TPR@1%FPR={scores['tpr_at_1pct_fpr']:.5f} "
            f"benign FPR@0.5={scores['benign_false_positive_rate_at_0_5']:.4%}"
        )

    architecture = {
        "numeric_features": len(numeric_features),
        "categorical_cardinalities": cardinalities,
        "embedding_dimensions": {
            name: embedding_dimension(cardinality)
            for name, cardinality in cardinalities.items()
        },
        "hidden_layers": [128, 64, 32],
        "activation": "ReLU",
        "dropout": config.dropout,
        "output": "one logit",
    }
    checkpoint = {
        "state_dict": best_state,
        "architecture": architecture,
        "selected_features": selected_features,
        "numeric_features": numeric_features,
        "categorical_features": categorical_features,
        "random_seed": config.seed,
        "best_epoch": best_epoch,
        "best_validation_bce": best_loss,
        "training_config": asdict(config),
        "metrics": metrics,
    }
    preprocessor = {
        "standard_scaler": scaler,
        "categorical_vocabularies": vocabularies,
        "isotonic_calibrator": calibrator,
        "selected_features": selected_features,
        "numeric_features": numeric_features,
        "metrics": metrics,
        "calibration_protocol": (
            "Validation data is used for both early stopping and isotonic calibration, "
            "matching the existing XGBoost baseline protocol."
        ),
    }
    artifact_dir.mkdir(parents=True, exist_ok=True)
    torch.save(checkpoint, artifact_dir / f"mlp_{tag}.pt")
    joblib.dump(preprocessor, artifact_dir / f"mlp_{tag}_preprocessor.joblib")
    print(f"saved to {artifact_dir / f'mlp_{tag}'}*")
    return checkpoint


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", choices=tuple(DATASETS), default="cic2017")
    parser.add_argument("--batch-size", type=int, default=TrainingConfig.batch_size)
    parser.add_argument("--max-epochs", type=int, default=TrainingConfig.max_epochs)
    parser.add_argument("--patience", type=int, default=TrainingConfig.patience)
    parser.add_argument("--seed", type=int, default=TrainingConfig.seed)
    parser.add_argument("--threads", type=int, default=TrainingConfig.num_threads)
    parser.add_argument(
        "--shuffle-buffer-size", type=int, default=TrainingConfig.shuffle_buffer_size
    )
    args = parser.parse_args(argv)
    config = TrainingConfig(
        batch_size=args.batch_size,
        max_epochs=args.max_epochs,
        patience=args.patience,
        seed=args.seed,
        num_threads=args.threads,
        shuffle_buffer_size=args.shuffle_buffer_size,
    )
    train_dataset(args.dataset, config=config)


if __name__ == "__main__":
    main()
