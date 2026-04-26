import { C as ConvexReactClient, a as ConvexHttpClient, g as getFunctionName, c as convexToJson } from "./convex.mjs";
import { n as notifyManager, h as hashKey } from "./tanstack__query-core.mjs";
const isServer = typeof window === "undefined";
function isConvexSkipped(queryKey) {
  return queryKey.length >= 2 && ["convexQuery", "convexAction"].includes(queryKey[0]) && queryKey[2] === "skip";
}
function isConvexQuery(queryKey) {
  return queryKey.length >= 2 && queryKey[0] === "convexQuery";
}
function isConvexAction(queryKey) {
  return queryKey.length >= 2 && queryKey[0] === "convexAction";
}
function hash(queryKey) {
  return `convexQuery|${getFunctionName(queryKey[1])}|${JSON.stringify(convexToJson(queryKey[2]))}`;
}
class ConvexQueryClient {
  convexClient;
  subscriptions;
  unsubscribe;
  // Only exists during SSR
  serverHttpClient;
  _queryClient;
  ssrQueryMode;
  get queryClient() {
    if (!this._queryClient) {
      throw new Error("ConvexQueryClient not connected to TanStack QueryClient.");
    }
    return this._queryClient;
  }
  constructor(client, options = {}) {
    if (typeof client === "string") {
      this.convexClient = new ConvexReactClient(client, options);
    } else {
      this.convexClient = client;
    }
    if (options.dangerouslyUseInconsistentQueriesDuringSSR) {
      this.ssrQueryMode = "inconsistent";
    } else {
      this.ssrQueryMode = "consistent";
    }
    this.subscriptions = {};
    if (options.queryClient) {
      this._queryClient = options.queryClient;
      this.unsubscribe = this.subscribeInner(options.queryClient.getQueryCache());
    }
    if (isServer) {
      this.serverHttpClient = new ConvexHttpClient(this.convexClient.url);
    }
  }
  /** Complete initialization of ConvexQueryClient by connecting a TanStack QueryClient */
  connect(queryClient) {
    if (this.unsubscribe) {
      throw new Error("already subscribed!");
    }
    this._queryClient = queryClient;
    this.unsubscribe = this.subscribeInner(queryClient.getQueryCache());
  }
  /** Update every query key. Probably not useful, don't use this. */
  onUpdate = () => {
    notifyManager.batch(() => {
      for (const key of Object.keys(this.subscriptions)) {
        this.onUpdateQueryKeyHash(key);
      }
    });
  };
  onUpdateQueryKeyHash(queryHash) {
    const subscription = this.subscriptions[queryHash];
    if (!subscription) {
      throw new Error(`Internal ConvexQueryClient error: onUpdateQueryKeyHash called for ${queryHash}`);
    }
    const queryCache = this.queryClient.getQueryCache();
    const query = queryCache.get(queryHash);
    if (!query)
      return;
    const { queryKey, watch } = subscription;
    let result;
    try {
      result = { ok: true, value: watch.localQueryResult() };
    } catch (error) {
      result = { ok: false, error };
    }
    if (result.ok) {
      const value = result.value;
      this.queryClient.setQueryData(queryKey, (prev) => {
        if (prev === void 0) {
          return void 0;
        }
        return value;
      });
    } else {
      const { error } = result;
      query?.setState({
        error,
        errorUpdateCount: query.state.errorUpdateCount + 1,
        errorUpdatedAt: Date.now(),
        fetchFailureCount: query.state.fetchFailureCount + 1,
        fetchFailureReason: error,
        fetchStatus: "idle",
        status: "error"
      }, { meta: "set by ConvexQueryClient" });
    }
  }
  subscribeInner(queryCache) {
    if (isServer)
      return () => {
      };
    return queryCache.subscribe((event) => {
      if (!isConvexQuery(event.query.queryKey)) {
        return;
      }
      if (isConvexSkipped(event.query.queryKey)) {
        return;
      }
      switch (event.type) {
        // A query has been GC'd so no stale value will be available.
        // In Convex this means we should unsubscribe.
        case "removed": {
          this.subscriptions[event.query.queryHash].unsubscribe();
          delete this.subscriptions[event.query.queryHash];
          break;
        }
        // A query has been requested for the first time.
        // Subscribe to the query so we hold on to it.
        case "added": {
          const [_, func, args, _opts] = event.query.queryKey;
          const watch = this.convexClient.watchQuery(
            func,
            args,
            // TODO pass journals through
            {}
          );
          const unsubscribe = watch.onUpdate(() => {
            this.onUpdateQueryKeyHash(event.query.queryHash);
          });
          this.subscriptions[event.query.queryHash] = {
            queryKey: event.query.queryKey,
            watch,
            unsubscribe
          };
          break;
        }
        // Runs when a useQuery mounts
        case "observerAdded": {
          break;
        }
        // Runs when a useQuery unmounts
        case "observerRemoved": {
          if (event.query.getObserversCount() === 0) ;
          break;
        }
        // Fires once per useQuery hook
        case "observerResultsUpdated": {
          break;
        }
        case "updated": {
          if (event.action.type === "setState" && event.action.setStateOptions?.meta === "set by ConvexQueryClient") {
            break;
          }
          break;
        }
      }
    });
  }
  /**
   * Returns a promise for the query result of a query key containing
   * `['convexQuery', FunctionReference, args]` and subscribes via WebSocket
   * to future updates.
   *
   * You can provide a custom fetch function for queries that are not
   * Convex queries.
   */
  queryFn(otherFetch = throwBecauseNotConvexQuery) {
    return async (context) => {
      if (isConvexSkipped(context.queryKey)) {
        throw new Error("Skipped query should not actually be run, should { enabled: false }");
      }
      if (isConvexQuery(context.queryKey)) {
        const [_, func, args] = context.queryKey;
        if (isServer) {
          if (this.ssrQueryMode === "consistent") {
            return await this.serverHttpClient.consistentQuery(func, args);
          } else {
            return await this.serverHttpClient.query(func, args);
          }
        } else {
          return await this.convexClient.query(func, args);
        }
      }
      if (isConvexAction(context.queryKey)) {
        const [_, func, args] = context.queryKey;
        if (isServer) {
          return await this.serverHttpClient.action(func, args);
        } else {
          return await this.convexClient.action(func, args);
        }
      }
      return otherFetch(context);
    };
  }
  /**
   * Set this globally to use Convex query functions.
   *
   * ```ts
   * const queryClient = new QueryClient({
   *   defaultOptions: {
   *    queries: {
   *       queryKeyHashFn: convexQueryClient.hashFn(),
   *     },
   *   },
   * });
   *
   * You can provide a custom hash function for keys that are not for Convex
   * queries.
   */
  hashFn(otherHashKey = hashKey) {
    return (queryKey) => {
      if (isConvexQuery(queryKey)) {
        return hash(queryKey);
      }
      return otherHashKey(queryKey);
    };
  }
  /**
   * Query options factory for Convex query function subscriptions.
   *
   * ```
   * useQuery(client.queryOptions(api.foo.bar, args))
   * ```
   *
   * If you need to specify other options spread it:
   * ```
   * useQuery({
   *   ...convexQueryClient.queryOptions(api.foo.bar, args),
   *   placeholderData: { name: "me" }
   * });
   * ```
   */
  queryOptions = (funcRef, queryArgs) => {
    return {
      queryKey: [
        "convexQuery",
        // Make query key serializable
        getFunctionName(funcRef),
        // TODO bigints are not serializable
        queryArgs
      ],
      queryFn: this.queryFn(),
      staleTime: Infinity
      // We cannot set hashFn here, see
      // https://github.com/TanStack/query/issues/4052#issuecomment-1296174282
      // so the developer must set it globally.
    };
  };
}
function throwBecauseNotConvexQuery(context) {
  throw new Error("Query key is not for a Convex Query: " + context.queryKey);
}
export {
  ConvexQueryClient as C
};
