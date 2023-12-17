-- v15: Remove unused columns in puppet table
ALTER TABLE puppet DROP COLUMN next_batch;
ALTER TABLE puppet DROP COLUMN base_url;
