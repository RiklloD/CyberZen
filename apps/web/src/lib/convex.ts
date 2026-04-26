import { anyApi, componentsGeneric } from "convex/server";
import type { GenericId } from "convex/values";

export const api = anyApi;
export const internal = anyApi;
export const components = componentsGeneric();

export type Id<TableName extends string> = GenericId<TableName>;

export type Doc<TableName extends string> = {
	_id: Id<TableName>;
	_creationTime: number;
} & Record<string, unknown>;

export type TableNames = string;

export type DataModel = Record<string, unknown>;
