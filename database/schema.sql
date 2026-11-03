-- BI-Safe PostgreSQL schema — Step 3
-- Only the predictions table for now. More tables added in later steps.
-- Idempotent: safe to run multiple times.

CREATE TABLE IF NOT EXISTS predictions (
    id              BIGSERIAL PRIMARY KEY,
    event_id        TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    score           DOUBLE PRECISION NOT NULL,
    is_anomaly      BOOLEAN NOT NULL,
    ground_truth    TEXT,
    -- Features (20) — kept for reproducibility and future retraining
    source_port            DOUBLE PRECISION,
    destination_port       DOUBLE PRECISION,
    duration               DOUBLE PRECISION,
    bytes_sent             DOUBLE PRECISION,
    bytes_received         DOUBLE PRECISION,
    packets_sent           DOUBLE PRECISION,
    packets_received       DOUBLE PRECISION,
    packet_size            DOUBLE PRECISION,
    flow_bytes_per_s       DOUBLE PRECISION,
    flow_packets_per_s     DOUBLE PRECISION,
    syn_flag_count         DOUBLE PRECISION,
    ack_flag_count         DOUBLE PRECISION,
    psh_flag_count         DOUBLE PRECISION,
    fwd_packet_len_std     DOUBLE PRECISION,
    bwd_packet_len_std     DOUBLE PRECISION,
    avg_packet_size        DOUBLE PRECISION,
    down_up_ratio          DOUBLE PRECISION,
    init_win_bytes_fwd     DOUBLE PRECISION,
    flow_iat_mean          DOUBLE PRECISION,
    flow_iat_std           DOUBLE PRECISION,
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_predictions_timestamp   ON predictions (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_predictions_is_anomaly  ON predictions (is_anomaly) WHERE is_anomaly = TRUE;
CREATE INDEX IF NOT EXISTS idx_predictions_event_id    ON predictions (event_id);
-- =====================================================================
-- Step 4: alerts
-- =====================================================================

CREATE TABLE IF NOT EXISTS alerts (
    id             BIGSERIAL PRIMARY KEY,
    prediction_id  BIGINT NOT NULL REFERENCES predictions(id) ON DELETE CASCADE,
    event_id       TEXT NOT NULL,
    alert_type     TEXT NOT NULL,     
    severity       TEXT NOT NULL,     
    status         TEXT NOT NULL,     
    sent_at        TIMESTAMPTZ,
    error_message  TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_prediction_id ON alerts (prediction_id);
CREATE INDEX IF NOT EXISTS idx_alerts_event_id      ON alerts (event_id);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at    ON alerts (created_at DESC);
