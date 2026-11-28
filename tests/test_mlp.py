import numpy as np
import pandas as pd
import pytest
import torch

from evasight.models.mlp import (
    MLP,
    _bounded_shuffle_batches,
    build_category_vocabularies,
    embedding_dimension,
    encode_categorical,
    fit_numeric_scaler,
    seed_everything,
    validate_numerical_features,
)


def test_numerical_only_forward_has_one_logit_per_row():
    model = MLP(numeric_features=5)

    output = model(torch.randn(7, 5))

    assert output.shape == (7, 1)


def test_categorical_embedding_forward_has_one_logit_per_row():
    model = MLP(numeric_features=3, categorical_cardinalities={"proto": 4, "state": 2})

    categories = torch.tensor(
        [[0, 1], [1, 0], [2, 1], [3, 2], [4, 0], [0, 2]]
    )
    output = model(torch.randn(6, 3), categories)

    assert output.shape == (6, 1)


def test_unknown_embedding_stays_zero_after_optimizer_update():
    model = MLP(numeric_features=1, categorical_cardinalities={"proto": 3})
    optimizer = torch.optim.Adam(model.parameters(), lr=0.1)
    numerical = torch.ones(8, 1)
    unknown_categories = torch.zeros(8, 1, dtype=torch.long)

    loss = model(numerical, unknown_categories).sum()
    loss.backward()
    optimizer.step()

    unknown_embedding = model.embeddings[0].weight[0]
    torch.testing.assert_close(unknown_embedding, torch.zeros_like(unknown_embedding))
    torch.testing.assert_close(
        model.embeddings[0].weight.grad[0],
        torch.zeros_like(model.embeddings[0].weight.grad[0]),
    )


def test_forward_rejects_missing_categorical_input():
    model = MLP(numeric_features=2, categorical_cardinalities={"service": 3})

    with pytest.raises(ValueError, match="categorical input is required"):
        model(torch.randn(2, 2))


def test_category_vocabularies_are_built_from_training_values_only():
    train = pd.DataFrame({"proto": ["tcp", "udp", "tcp"], "service": ["http", "dns", "http"]})
    vocabularies = build_category_vocabularies(train, ("proto", "service"))

    assert vocabularies == {
        "proto": {"tcp": 1, "udp": 2},
        "service": {"dns": 1, "http": 2},
    }


def test_unseen_categories_map_to_reserved_unk_index():
    train = pd.DataFrame({"proto": ["tcp"], "service": ["http"], "state": ["FIN"]})
    vocabularies = build_category_vocabularies(train)
    held_out = pd.DataFrame(
        {"proto": ["ACC", "tcp"], "service": ["CLO", "http"], "state": ["unknown", "FIN"]}
    )

    encoded = encode_categorical(held_out, vocabularies)

    np.testing.assert_array_equal(encoded[0], [0, 0, 0])
    np.testing.assert_array_equal(encoded[1], [1, 1, 1])


def test_missing_categories_map_to_unk_index():
    vocabularies = build_category_vocabularies(pd.DataFrame({"proto": ["tcp"]}), ("proto",))

    encoded = encode_categorical(pd.DataFrame({"proto": [None, "tcp"]}), vocabularies)

    np.testing.assert_array_equal(encoded[:, 0], [0, 1])


def test_scaler_is_fitted_using_training_data_only():
    train = pd.DataFrame({"bytes": [0.0, 2.0], "packets": [10.0, 14.0]})
    validation = pd.DataFrame({"bytes": [100.0], "packets": [1000.0]})
    scaler = fit_numeric_scaler(train, ["bytes", "packets"])
    transformed_validation = scaler.transform(validation.to_numpy(dtype=np.float32))

    np.testing.assert_allclose(scaler.mean_, [1.0, 12.0])
    np.testing.assert_allclose(transformed_validation, [[99.0, 494.0]])


@pytest.mark.parametrize("bad_value", [np.nan, np.inf, -np.inf])
def test_non_finite_numerical_values_are_rejected(bad_value):
    with pytest.raises(ValueError, match="NaN or infinity"):
        validate_numerical_features(np.array([[1.0, bad_value]], dtype=np.float32))


def test_scaler_rejects_non_finite_training_values():
    train = pd.DataFrame({"duration": [1.0, np.inf]})

    with pytest.raises(ValueError, match="training numerical features"):
        fit_numeric_scaler(train, ["duration"])


def test_initialization_is_reproducible_with_fixed_seed():
    seed_everything(42, num_threads=1)
    first = MLP(4, {"proto": 5})
    first_state = {name: tensor.clone() for name, tensor in first.state_dict().items()}

    seed_everything(42, num_threads=1)
    second = MLP(4, {"proto": 5})

    for name, tensor in second.state_dict().items():
        torch.testing.assert_close(tensor, first_state[name])


@pytest.mark.parametrize(
    ("cardinality", "expected"), [(1, 2), (4, 2), (9, 3), (10_000, 50)]
)
def test_embedding_dimension_rule_is_deterministic(cardinality, expected):
    assert embedding_dimension(cardinality) == expected


@pytest.mark.parametrize(
    "kwargs",
    [
        {"batch_size": 0},
        {"max_epochs": 0},
        {"patience": 0},
        {"num_threads": 0},
        {"shuffle_buffer_size": 0},
        {"dropout": 1.0},
    ],
)
def test_invalid_training_configuration_is_rejected(kwargs):
    from evasight.models.mlp import TrainingConfig

    with pytest.raises(ValueError):
        TrainingConfig(**kwargs)


def _collect_shuffled_records(seed, epoch, buffer_size=4, output_batch_size=3):
    batches = [
        (
            np.arange(start, start + count, dtype=np.float32).reshape(-1, 1),
            np.arange(start + 100, start + count + 100, dtype=np.int64).reshape(-1, 1),
            np.arange(start, start + count, dtype=np.int64) % 2,
        )
        for start, count in ((0, 3), (3, 2), (5, 4))
    ]
    rng = np.random.default_rng(seed + epoch)
    shuffled = list(
        _bounded_shuffle_batches(iter(batches), buffer_size, rng, output_batch_size)
    )
    return tuple(np.concatenate([batch[index] for batch in shuffled]) for index in range(3))


def test_bounded_shuffle_emits_each_aligned_record_exactly_once():
    numerical, categorical, labels = _collect_shuffled_records(seed=42, epoch=1)

    assert sorted(numerical[:, 0].tolist()) == list(range(9))
    np.testing.assert_array_equal(categorical[:, 0], numerical[:, 0] + 100)
    np.testing.assert_array_equal(labels, numerical[:, 0].astype(np.int64) % 2)


def test_bounded_shuffle_is_deterministic_for_same_seed_and_epoch():
    first = _collect_shuffled_records(seed=42, epoch=2)
    second = _collect_shuffled_records(seed=42, epoch=2)

    for first_column, second_column in zip(first, second):
        np.testing.assert_array_equal(first_column, second_column)


def test_bounded_shuffle_changes_order_between_epochs():
    first, _, _ = _collect_shuffled_records(seed=42, epoch=1)
    second, _, _ = _collect_shuffled_records(seed=42, epoch=2)

    assert not np.array_equal(first, second)


def test_bounded_shuffle_mixes_records_across_source_batches():
    numerical, _, _ = _collect_shuffled_records(
        seed=42, epoch=1, buffer_size=4, output_batch_size=1
    )
    source_batches = np.where(
        numerical[:, 0] < 3, 0, np.where(numerical[:, 0] < 5, 1, 2)
    )

    assert np.count_nonzero(source_batches[1:] != source_batches[:-1]) > 2


def test_bounded_shuffle_respects_configured_buffer_capacity():
    consumed = []

    def one_record_batches():
        for record in range(8):
            consumed.append(record)
            yield (
                np.array([[record]], dtype=np.float32),
                None,
                np.array([record], dtype=np.int64),
            )

    shuffled = _bounded_shuffle_batches(
        one_record_batches(), 3, np.random.default_rng(42), output_batch_size=1
    )

    next(shuffled)

    assert consumed == [0, 1, 2, 3]
