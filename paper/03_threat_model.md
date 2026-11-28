# 3. Threat model

We consider an attacker who sends malicious traffic into a monitored network and wants each malicious flow to be labelled benign. The attack happens at test time against a model that is already trained; we do not consider poisoning of the training data. The defender is a flow-based network intrusion detection system. A flow meter (CICFlowMeter for CIC-IDS2017 and CSE-CIC-IDS2018, Argus and Zeek for UNSW-NB15) turns the packets of each flow into a fixed set of features. The baseline classifier gives each flow an attack score; a score of 0.5 or higher is the project's operating threshold. The calibrated XGBoost model is the established baseline; MLP results are tracked separately.

The implemented search can query the calibrated attack score but does not read model parameters or gradients. The attack runner uses the isotonic-calibrated probability. It therefore assumes score access, not white-box access and not merely label-only access. Score access is a stronger attacker capability than observing only an alert label. Its practical availability must be justified for any deployment scenario; it is not assumed to be universal.

The attacker controls only its own packets, which are the forward direction in the CIC data and the source direction in UNSW-NB15. It can make two changes. It can pad the payload of its data packets, and it can delay its packets so that every gap between them grows. Both changes are relative to the flow itself. With budget ε, padding adds at most ε times the flow's mean payload per data packet to each data packet, and delay adds at most ε times the flow's mean gap between the attacker's packets to each gap. We test ε ∈ {0.1, 0.25, 0.5, 1.0}. Budgets are cumulative: an attacker with budget ε may use any change found with a smaller budget. The attacker cannot add or remove packets, change TCP flags, ports or the protocol, or change anything the victim sends.

Several constraints keep every perturbed flow one that a real network could produce. No packet may exceed the maximum segment size of 1,460 bytes in the CIC datasets, and the mean source packet size may not exceed the 1,500-byte MTU in UNSW-NB15. Delays respect the timeouts of the flow meter, which we measured from the data: CICFlowMeter ends a flow after 120 s and treats a gap longer than 5 s as idle time, and Argus ends a flow after 60 s. A longer flow or gap would have been split or recorded differently by the real tool. In UNSW-NB15, which has no count of data packets, we assume that the SYN, the handshake ACK and the FIN of a TCP flow carry no payload. Every feature that depends on a changed value is recomputed, and each perturbed flow must pass validity rules that clean traffic satisfies: 13 rules for the CIC datasets and 5 for UNSW-NB15, each broken by less than 0.4% of clean training flows. Where a flow's features cannot be kept consistent, we leave the flow unchanged. In CIC-IDS2017 this applies to the 1.4% of attack flows with forward bulk activity. These choices can only lower the evasion we report.

Feature-controllability counts depend on the schema being described. The legacy
`configs/cic2017_controllability.csv` contains 77 features (15 free, 29 derived, 33 fixed).
The improved CIC-IDS2017 table contains 83 (15 free, 30 derived, 38 fixed); the improved
CSE-CIC-IDS2018 release uses the same feature schema. The UNSW-NB15 table contains 42
features (3 free, 6 derived, 33 fixed). These are classifications in project configuration files,
not independent proof that an attacker can realize every nominally free value.

In particular, `init_win_bytes_forward` is classified as free in the CIC feature table because
the sender's TCP stack can affect it. The implemented padding-and-delay transformations do not
change the initial window. For those experiments it is invariant, and the project's audit reports
that the sentinel value `-1` occurs in 43.1% of benign flows and 0% of attack flows. This
capture-associated shortcut may support classification without representing malicious behaviour;
it is a confound and an ablation target, not evidence that explanations reveal evasion.

Out of scope are packet injection, dropped packets, model extraction, and an attacker who knows
about and adapts to an instability-based detector. The latter is a future adaptive-threat-model
extension. See `open_questions.md` for the unresolved operational assumptions.
