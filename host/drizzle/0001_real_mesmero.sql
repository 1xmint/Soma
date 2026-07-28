ALTER TABLE "observation_batches" ADD COLUMN "batch_id" text NOT NULL;--> statement-breakpoint
ALTER TABLE "observation_batches" ADD COLUMN "submitted_at" timestamp with time zone NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "observation_batches_user_batch_idx" ON "observation_batches" USING btree ("user_id","batch_id");