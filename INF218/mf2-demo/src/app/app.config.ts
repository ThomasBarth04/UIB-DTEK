import { ApplicationConfig, provideBrowserGlobalErrorListeners, provideZoneChangeDetection } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideI18n } from 'mf2-i18n';

import { routes } from './app.routes';

const catalogs = {
  en: {
    greeting: 'Hello from the MF2 pipe!',
    welcome: 'Nice to see you, {name}!'
  },
  nb: {
    greeting: 'Hei fra MF2-pipen!',
    welcome: 'Hyggelig å se deg, {name}!'
  }
};

export const appConfig: ApplicationConfig = {
  providers: [
    provideBrowserGlobalErrorListeners(),
    provideZoneChangeDetection({ eventCoalescing: true }),
    provideRouter(routes),
    provideI18n({
      defaultLocale: 'en',
      catalogs
    })
  ]
};
