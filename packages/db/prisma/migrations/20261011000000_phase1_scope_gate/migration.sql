-- AlterTable
ALTER TABLE "Org" ADD COLUMN     "killSwitchById" UUID;

-- AlterTable
ALTER TABLE "Scope" ADD COLUMN     "cloudRoleArn" TEXT,
ADD COLUMN     "externalId" TEXT,
ADD COLUMN     "lastVerificationAt" TIMESTAMP(3),
ADD COLUMN     "lastVerificationError" TEXT;

-- AlterTable
ALTER TABLE "Scan" ADD COLUMN     "approvedAt" TIMESTAMP(3),
ADD COLUMN     "killedById" UUID;

-- CreateIndex
CREATE UNIQUE INDEX "Scope_externalId_key" ON "Scope"("externalId");

