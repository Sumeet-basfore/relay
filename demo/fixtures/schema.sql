-- Relay Demo PostgreSQL Schema Fixture
CREATE TABLE IF NOT EXISTS demo_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS demo_audit (
    id SERIAL PRIMARY KEY,
    action_type VARCHAR(50) NOT NULL,
    performed_by VARCHAR(50) NOT NULL,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO demo_users (username, email, role) VALUES 
    ('alice_operator', 'alice@corp.internal', 'admin'),
    ('bob_analyst', 'bob@corp.internal', 'viewer')
ON CONFLICT (username) DO NOTHING;
