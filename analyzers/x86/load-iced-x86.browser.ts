"use strict";

const getIcedX86ModuleUrl = (): string =>
  new URL(`${import.meta.env.BASE_URL}vendor/iced-x86/iced_x86.js`, window.location.href).href;

export const loadIcedX86 = async (): Promise<unknown> =>
  import(/* @vite-ignore */ getIcedX86ModuleUrl());
