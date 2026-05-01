import { Router, type IRouter } from "express";
import healthRouter from "./health";
import authRouter from "./auth";
import dashboardRouter from "./dashboard";
import scansRouter from "./scans";
import findingsRouter from "./findings";
import targetsRouter from "./targets";
import settingsRouter from "./settings";
import remediationsRouter from "./remediations";

const router: IRouter = Router();

router.use(healthRouter);
router.use(authRouter);
router.use(dashboardRouter);
router.use(scansRouter);
router.use(findingsRouter);
router.use(targetsRouter);
router.use(settingsRouter);
router.use(remediationsRouter);

export default router;
