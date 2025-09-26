import { Component, inject } from '@angular/core';
import { I18nPipe, I18nStore } from 'mf2-i18n';

@Component({
  standalone: true,
  selector: 'app-root',
  imports: [I18nPipe],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
  private readonly store = inject(I18nStore);

  protected readonly displayName = 'Student';

  protected setLocale(locale: string): void {
    this.store.setLocale(locale);
  }
}
