-- DropIndex
DROP INDEX "Finding_fingerprint_idx";

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "evidence" JSONB,
ADD COLUMN     "firstSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "lastScanId" UUID,
ADD COLUMN     "lastSeenAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ALTER COLUMN "fingerprint" SET NOT NULL;

-- CreateIndex
CREATE INDEX "Finding_severity_status_idx" ON "Finding"("severity", "status");

-- CreateIndex
CREATE UNIQUE INDEX "Finding_assetId_fingerprint_key" ON "Finding"("assetId", "fingerprint");

