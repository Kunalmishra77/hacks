-- CreateEnum
CREATE TYPE "Criticality" AS ENUM ('LOW', 'MEDIUM', 'HIGH');

-- AlterTable
ALTER TABLE "Scope" ADD COLUMN     "criticality" "Criticality" NOT NULL DEFAULT 'MEDIUM';

-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "enrichedAt" TIMESTAMP(3),
ADD COLUMN     "epss" DOUBLE PRECISION,
ADD COLUMN     "kevListed" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "riskScore" INTEGER;

