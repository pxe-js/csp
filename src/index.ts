import builder from "content-security-policy-builder";
import { Middleware, NextFunction, Context } from "@pxe/server";

declare namespace CSP {
    export type SrcValue = boolean | string | string[];

    export type FetchDirective = "child" | "connect" | "font" | "frame" | "img" | "manifest" | "media" | "object" | "prefetch" | "script" | "style" | "worker";

    export interface Options {
        readonly src: {
            [key in FetchDirective]?: SrcValue;
        } & {
            [key: string]: SrcValue;
        }

        report: string;
    }
}

function getHeader(srcs: Record<string, CSP.SrcValue>, reportURI: string) {
    let headerValue = builder({
        directives: srcs
    });

    if (reportURI)
        headerValue += `; report-uri ${reportURI}; report-to ${reportURI}`;

    return headerValue;
}

interface CSP extends Middleware { }

class CSP extends Function {
    private headerValue: string;

    constructor(readonly options?: CSP.Options) {
        super();

        if (options) {
            // Parse srcs
            let srcs = {};
            for (const source in options.src)
                srcs[source + "-src"] = options.src[source];

            this.headerValue = getHeader(srcs, options.report);
        } else
            this.headerValue = "default-src 'self'";

        return new Proxy(this, {
            apply(target, thisArg, args) {
                return target.invoke(...args as [any, any, any]);
            }
        })
    }

    async invoke(ctx: Context, next: NextFunction, ...args: any[]) {
        ctx.response.headers["Content-Security-Policy"] = this.headerValue;

        return next(...args);
    }
}

export = CSP;