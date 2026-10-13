-- AlterTable
ALTER TABLE "Finding" ADD COLUMN     "aiAdvice" JSONB,
ADD COLUMN     "aiAdviceAt" TIMESTAMP(3),
ADD COLUMN     "aiModel" TEXT;

