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

interface CSP extends Middleware { }

class CSP extends Function {
    private srcs: Record<string, CSP.SrcValue>;
    private reportURI: string;

    constructor(readonly options?: CSP.Options) {
        super();

        if (options) {
            // Parse srcs
            this.srcs = {};
            for (const source in options.src)
                this.srcs[source + "-src"] = options.src[source];

            this.reportURI = options.report;
        }

        return new Proxy(this, {
            apply(target, thisArg, args) {
                return target.invoke(...args as [any, any, any]);
            }
        })
    }

    async invoke(ctx: Context, next: NextFunction, ...args: any[]) {
        let headerValue = "";

        if (!this.srcs)
            headerValue = "default-src 'self'";
        else 
            headerValue = builder({
                directives: this.srcs
            });

        if (this.reportURI)
            headerValue += `; report-uri ${this.reportURI}; report-to ${this.reportURI}`;

        ctx.response.headers["Content-Security-Policy"] = headerValue;

        return next(...args);
    }
}

export = CSP;