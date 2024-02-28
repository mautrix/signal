-- v20 (compatible with v17+): Add profile fetch timestamp for puppets
ALTER TABLE puppet ADD profile_fetched_at BIGINT;
