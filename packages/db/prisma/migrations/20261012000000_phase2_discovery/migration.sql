-- AlterTable
ALTER TABLE "Asset" ADD COLUMN     "discoveredByScanId" UUID,
ADD COLUMN     "metadata" JSONB;

