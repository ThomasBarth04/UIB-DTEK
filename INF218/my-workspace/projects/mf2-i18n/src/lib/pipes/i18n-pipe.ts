import { Pipe, PipeTransform } from '@angular/core';
import { generate } from '../mf2';
import { I18nStore } from '../store';

@Pipe({
  name: 'i18n',
  standalone: true,
  pure: true
})
export class I18nPipe implements PipeTransform {
  constructor(
    private store: I18nStore
  ) { }

  transform(key: string, args: Record<string, unknown>): string {
    return this.store.format(key, args,)
  }

}
