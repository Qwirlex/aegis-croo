from aegis_engine.scoring import confidence_for, risk_score, verdict_for


def test_ten_lows_never_outrank_one_critical():
    lows = [{"severity": "low"} for _ in range(10)]
    assert risk_score(lows) < risk_score([{"severity": "critical"}])


def test_score_is_capped_per_severity_band():
    five_mediums = [{"severity": "medium"} for _ in range(5)]
    two_mediums = [{"severity": "medium"} for _ in range(2)]
    assert risk_score(five_mediums) == risk_score(two_mediums + two_mediums)


def test_clean_contract_scores_zero_and_reads_as_ok():
    assert risk_score([]) == 0
    assert verdict_for(0, []) == "looks_ok"


def test_score_never_exceeds_one_hundred():
    everything = [{"severity": s} for s in ("critical", "critical", "high", "high", "medium")]
    assert risk_score(everything) == 100


def test_an_unknown_severity_scores_nothing_rather_than_raising():
    assert risk_score([{"severity": "catastrophic"}]) == 0
    assert risk_score([{}]) == 0


def test_verdict_follows_the_worst_real_finding():
    assert verdict_for(90, [{"severity": "critical"}]) == "critical_risk"
    assert verdict_for(40, [{"severity": "high"}]) == "high_risk"
    assert verdict_for(20, [{"severity": "medium"}]) == "caution"
    assert verdict_for(5, [{"severity": "info"}]) == "looks_ok"


def test_verdict_ignores_the_score_and_reads_the_worst_finding():
    # A single critical outranks a pile of mediums even when the pile scores higher.
    mediums = [{"severity": "medium"} for _ in range(4)]
    assert verdict_for(risk_score(mediums), mediums) == "caution"
    assert verdict_for(0, [{"severity": "critical"}]) == "critical_risk"


def test_confidence_is_high_only_when_everything_went_right():
    assert confidence_for(source_verified=True, lenses_run=6, lenses_total=6, refuted_share=0.3) == "high"


def test_confidence_drops_when_a_lens_was_skipped():
    assert confidence_for(source_verified=True, lenses_run=4, lenses_total=6, refuted_share=0.1) == "medium"


def test_confidence_is_low_for_unverified_source_or_a_mostly_refuted_run():
    assert confidence_for(source_verified=False, lenses_run=6, lenses_total=6, refuted_share=0.1) == "medium"
    assert confidence_for(source_verified=True, lenses_run=6, lenses_total=6, refuted_share=0.9) == "low"


def test_no_lens_ran_at_all_is_low_not_high():
    assert confidence_for(source_verified=True, lenses_run=0, lenses_total=6, refuted_share=0.0) == "low"


def test_a_zero_lens_total_does_not_divide_by_zero_or_claim_high():
    assert confidence_for(source_verified=True, lenses_run=0, lenses_total=0, refuted_share=0.0) == "low"
