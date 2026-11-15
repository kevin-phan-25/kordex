-- Rotate bounded admission scans so one saturated fleet/site cannot starve later targets.
ALTER TABLE campaigns ADD COLUMN admission_cursor integer NOT NULL DEFAULT -1;
