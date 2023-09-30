-- v14: Remove redundant notice_room column from users
UPDATE "user" SET management_room = COALESCE(management_room, notice_room);
ALTER TABLE "user" DROP COLUMN notice_room;
