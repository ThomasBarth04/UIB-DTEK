import { InjectionToken } from '@angular/core';
export type Catalogs = Record<string, Record<string, string>>;

export interface I18nConfig {
  defaultLocale: string;
  catalogs: Catalogs;
}

export const I18N_CONFIG = new InjectionToken<I18nConfig>('I18N_CONFIG');
