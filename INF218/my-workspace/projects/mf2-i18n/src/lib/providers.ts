import { EnvironmentProviders, makeEnvironmentProviders } from '@angular/core';
import { I18N_CONFIG, I18nConfig } from './types';

export function provideI18n(config: I18nConfig): EnvironmentProviders {
  return makeEnvironmentProviders([
    {
      provide: I18N_CONFIG,
      useValue: config,
    },
  ]);
}
