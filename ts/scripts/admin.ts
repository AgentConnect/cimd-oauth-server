import { required, storeFromEnv } from "../examples/config.js";
const store = storeFromEnv();
try {
  switch (process.argv[2]) {
    case "block":
      await store.blockClient(required("CLIENT_ID"), true);
      break;
    case "unblock":
      await store.blockClient(required("CLIENT_ID"), false);
      break;
    case "disable-grant":
      await store.disableGrant(required("CLIENT_ID"), required("GRANT_ID"));
      break;
    case "cleanup":
      await store.cleanup();
      break;
    case "invalidate-recovery":
      await store.invalidateForRecovery();
      break;
    default:
      throw new Error(
        "Expected block, unblock, disable-grant, cleanup or invalidate-recovery",
      );
  }
  process.stdout.write("Administrative operation completed\n");
} finally {
  await store.pool.end();
}
