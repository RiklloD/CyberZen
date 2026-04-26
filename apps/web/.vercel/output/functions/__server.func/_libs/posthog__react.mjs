import { s as sa } from "./posthog-js.mjs";
import { r as reactExports, R as React } from "./react.mjs";
var defaultPostHogInstance;
function setDefaultPostHogInstance(instance) {
  defaultPostHogInstance = instance;
}
function getDefaultPostHogInstance() {
  return defaultPostHogInstance;
}
var PostHogContext = reactExports.createContext({
  get client() {
    return getDefaultPostHogInstance();
  },
  bootstrap: void 0
});
function isDeepEqual(obj1, obj2, visited) {
  if (visited === void 0) {
    visited = /* @__PURE__ */ new WeakMap();
  }
  if (obj1 === obj2) {
    return true;
  }
  if (typeof obj1 !== "object" || obj1 === null || typeof obj2 !== "object" || obj2 === null) {
    return false;
  }
  if (visited.has(obj1) && visited.get(obj1) === obj2) {
    return true;
  }
  visited.set(obj1, obj2);
  var keys1 = Object.keys(obj1);
  var keys2 = Object.keys(obj2);
  if (keys1.length !== keys2.length) {
    return false;
  }
  for (var _i = 0, keys1_1 = keys1; _i < keys1_1.length; _i++) {
    var key = keys1_1[_i];
    if (!keys2.includes(key)) {
      return false;
    }
    if (!isDeepEqual(obj1[key], obj2[key], visited)) {
      return false;
    }
  }
  return true;
}
function PostHogProvider(_a) {
  var _b, _c;
  var children = _a.children, client = _a.client, apiKey = _a.apiKey, options = _a.options;
  var previousInitializationRef = reactExports.useRef(null);
  var posthog = reactExports.useMemo(function() {
    if (client) {
      if (apiKey) {
        console.warn("[PostHog.js] You have provided both `client` and `apiKey` to `PostHogProvider`. `apiKey` will be ignored in favour of `client`.");
      }
      if (options) {
        console.warn("[PostHog.js] You have provided both `client` and `options` to `PostHogProvider`. `options` will be ignored in favour of `client`.");
      }
      return client;
    }
    var defaultInstance = getDefaultPostHogInstance();
    if (apiKey) {
      return defaultInstance;
    }
    console.warn("[PostHog.js] No `apiKey` or `client` were provided to `PostHogProvider`. Using default global `window.posthog` instance. You must initialize it manually. This is not recommended behavior.");
    return defaultInstance;
  }, [client, apiKey, JSON.stringify(options)]);
  reactExports.useEffect(function() {
    if (client) {
      return;
    }
    var defaultInstance = getDefaultPostHogInstance();
    var previousInitialization = previousInitializationRef.current;
    if (!previousInitialization) {
      if (defaultInstance.__loaded) {
        console.warn("[PostHog.js] `posthog` was already loaded elsewhere. This may cause issues.");
      }
      defaultInstance.init(apiKey, options);
      previousInitializationRef.current = {
        apiKey,
        options: options !== null && options !== void 0 ? options : {}
      };
    } else {
      if (apiKey !== previousInitialization.apiKey) {
        console.warn("[PostHog.js] You have provided a different `apiKey` to `PostHogProvider` than the one that was already initialized. This is not supported by our provider and we'll keep using the previous key. If you need to toggle between API Keys you need to control the `client` yourself and pass it in as a prop rather than an `apiKey` prop.");
      }
      if (options && !isDeepEqual(options, previousInitialization.options)) {
        defaultInstance.set_config(options);
      }
      previousInitializationRef.current = {
        apiKey,
        options: options !== null && options !== void 0 ? options : {}
      };
    }
  }, [client, apiKey, JSON.stringify(options)]);
  return React.createElement(PostHogContext.Provider, { value: { client: posthog, bootstrap: (_b = options === null || options === void 0 ? void 0 : options.bootstrap) !== null && _b !== void 0 ? _b : (_c = client === null || client === void 0 ? void 0 : client.config) === null || _c === void 0 ? void 0 : _c.bootstrap } }, children);
}
var isFunction = function(f) {
  return typeof f === "function";
};
var extendStatics = function(d, b) {
  extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(d2, b2) {
    d2.__proto__ = b2;
  } || function(d2, b2) {
    for (var p in b2) if (Object.prototype.hasOwnProperty.call(b2, p)) d2[p] = b2[p];
  };
  return extendStatics(d, b);
};
function __extends(d, b) {
  if (typeof b !== "function" && b !== null)
    throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
  extendStatics(d, b);
  function __() {
    this.constructor = d;
  }
  d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
}
typeof SuppressedError === "function" ? SuppressedError : function(error, suppressed, message) {
  var e = new Error(message);
  return e.name = "SuppressedError", e.error = error, e.suppressed = suppressed, e;
};
var INITIAL_STATE = {
  componentStack: null,
  exceptionEvent: null,
  error: null
};
var __POSTHOG_ERROR_MESSAGES = {
  INVALID_FALLBACK: "[PostHog.js][PostHogErrorBoundary] Invalid fallback prop, provide a valid React element or a function that returns a valid React element."
};
(function(_super) {
  __extends(PostHogErrorBoundary, _super);
  function PostHogErrorBoundary(props) {
    var _this = _super.call(this, props) || this;
    _this.state = INITIAL_STATE;
    return _this;
  }
  PostHogErrorBoundary.prototype.componentDidCatch = function(error, errorInfo) {
    var additionalProperties = this.props.additionalProperties;
    var currentProperties;
    if (isFunction(additionalProperties)) {
      currentProperties = additionalProperties(error);
    } else if (typeof additionalProperties === "object") {
      currentProperties = additionalProperties;
    }
    var client = this.context.client;
    var exceptionEvent = client.captureException(error, currentProperties);
    var componentStack = errorInfo.componentStack;
    this.setState({
      error,
      componentStack: componentStack !== null && componentStack !== void 0 ? componentStack : null,
      exceptionEvent
    });
  };
  PostHogErrorBoundary.prototype.render = function() {
    var _a = this.props, children = _a.children, fallback = _a.fallback;
    var state = this.state;
    if (state.componentStack == null) {
      return isFunction(children) ? children() : children;
    }
    var element = isFunction(fallback) ? React.createElement(fallback, {
      error: state.error,
      componentStack: state.componentStack,
      exceptionEvent: state.exceptionEvent
    }) : fallback;
    if (React.isValidElement(element)) {
      return element;
    }
    console.warn(__POSTHOG_ERROR_MESSAGES.INVALID_FALLBACK);
    return React.createElement(React.Fragment, null);
  };
  PostHogErrorBoundary.contextType = PostHogContext;
  return PostHogErrorBoundary;
})(React.Component);
setDefaultPostHogInstance(sa);
export {
  PostHogProvider as P
};
