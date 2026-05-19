# soma-sense

Observer-side verification for AI agents — the sensorium.

This package is a thin re-export of [`soma-heart/sense`](https://www.npmjs.com/package/soma-heart). Install it if you only need observation and don't want to interact with the heart directly.

```ts
import { withSomaSense } from "soma-sense";

const transport = withSomaSense(new StdioServerTransport(), {
  onVerdict: (sessionId, verdict) => {
    if (verdict.status === "RED") denyAccess(sessionId);
  },
});
```

All exports come from `soma-heart/sense`. See the [soma-heart docs](https://github.com/1xmint/Soma) for full API reference.
