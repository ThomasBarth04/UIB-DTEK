import { Component, signal } from '@angular/core';
import { I18nPipe } from 'mf2-i18n'

@Component({
  standalone: true,
  selector: 'app-root',
  imports: [I18nPipe],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
  protected readonly title = signal('mf2-demo');
}
