-- DropIndex
DROP INDEX "Report_orgId_idx";

-- AlterTable
ALTER TABLE "Report" ADD COLUMN     "byteSize" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "content" TEXT,
ADD COLUMN     "summary" JSONB NOT NULL,
ADD COLUMN     "title" TEXT NOT NULL,
ALTER COLUMN "format" SET DEFAULT 'HTML',
ALTER COLUMN "storageUrl" DROP NOT NULL;

-- CreateIndex
CREATE INDEX "Report_orgId_createdAt_idx" ON "Report"("orgId", "createdAt");

