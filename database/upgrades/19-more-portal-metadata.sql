-- v19 (compatible with v17+): Add more metadata for portals
ALTER TABLE portal ADD COLUMN topic_set BOOLEAN NOT NULL DEFAULT false;
UPDATE portal SET topic_set=true WHERE topic<>'';
ALTER TABLE portal ADD COLUMN avatar_path TEXT NOT NULL DEFAULT '';
ALTER TABLE puppet ADD COLUMN avatar_path TEXT NOT NULL DEFAULT '';
