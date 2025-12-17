import { render, html } from './_uhtml.js';
import { activate_flashes, show_flash } from './_flashes.js';

/**
 * Format a key-value field
 *
 * TODO: check security!
 *
 * @param {*} key The key
 * @param {*} value The value
 * @param {*} options Object with options {optional: bool, className: string, long: bool}
 * @returns HTML text
 */
export function format_field(key, value, options = {}) {
  if (value === undefined || (options.optional && !value)) return null;

  const li = document.createElement('li');
  li.classList.add('field');
  if (options.className) li.classList.add(options.className);
  if (options.long) li.classList.add('long');

  const keySpan = document.createElement('span');
  keySpan.classList.add('key');
  keySpan.textContent = key;

  const valContainer = options.long
    ? document.createElement('div')
    : document.createElement('span');
  valContainer.classList.add('value');

  // always treat value as text (safe)
  valContainer.textContent = value || '';

  if (Array.isArray(options.appendNodes)) {
    for (const node of options.appendNodes) {
      if (node instanceof Node) valContainer.appendChild(node);
    }
  }

  li.appendChild(keySpan);
  li.appendChild(valContainer);

  return li;
}




function alreadyMyBuddy(u) {
  // true if current user has already added u
  return !!(u?.i_added || u?.added_by_me || u?.is_my_buddy || u?.is_buddy);
}

function isMutualBuddy(u) {
  // optional: show a badge for mutual relation if your API returns both sides
  // e.g., i_added (me -> them) and added_me (them -> me)
  return !!((u?.i_added || u?.added_by_me) && (u?.added_me || u?.added_by_them));
}

/**
 * Display a user as a HTML element
 *
 * TODO: check security!
 *
 * @param {*} user A user object
 * @param {*} elt An optional element to render the user into
 * @returns elt or a new element
 */
export function format_profile(user, elt) {
  if (!elt) elt = document.createElement('div');
  elt.classList.add('user');
  if (user.id == current_user_id) elt.classList.add('me');
  elt.dataset.userId = user.id;

  let colorAppendNodes = undefined;
  if (user?.color) {
    const colorBox = document.createElement('div');
    colorBox.className = 'color-sample';
    colorBox.style.background = user.color.trim();
    colorBox.setAttribute('aria-label', `Color sample: ${user.color}`);
    colorAppendNodes = [document.createTextNode(' '), colorBox];
  }

  // Clear previous content
  elt.innerHTML = '';
  // Profile picture (sanitized URL fallback)
  const img = document.createElement('img');
  img.src = user.picture_url?.startsWith('http') ? user.picture_url : './static/unknown.png';
  img.alt = `${user.username}'s profile picture`;
  elt.appendChild(img);

  // List wrapper
  const ul = document.createElement('ul');
  ul.classList.add('data');
  elt.appendChild(ul);

  const fields = [
    ['Username', user.username, { className: 'username' }],
    ['Name', user.name, { className: 'more' }],
    ['Birth date', user.birthdate, { className: 'more' }],
    ['Favourite colour', user.color, { className: 'more', appendNodes: colorAppendNodes }],
    ['About', user.about, { long: true, className: 'more' }],
  ];

  for (const [key, value, opts] of fields) {
    const li = format_field(key, value, opts);
    if (li) ul.appendChild(li);
  }

  const controls = document.createElement('div');
  controls.classList.add('controls');

  if (isMutualBuddy(user)) {
    const badge = document.createElement('span');
    badge.className = 'badge mutual';
    badge.textContent = 'Mutual buddies';
    controls.appendChild(badge);
  }

  if (current_user_id != user.id && !alreadyMyBuddy(user)) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.dataset.userId = user.id;
    btn.dataset.action = 'add_buddy';
    btn.textContent = 'Add buddy';
    controls.appendChild(btn);
  }

  elt.appendChild(controls);
  return elt;
}


/**
 * Perform an action, such as a button click.
 *
 * Get the action to perform and any arguments from the 'data-*' attributes on the button element.
 *
 * @param {*} element A button element with `data-action="…"` set
 * @returns true if action was performed
 */
export async function do_action(element) {
  if (element.dataset.action === 'add_buddy') {
    const result = await fetch_json(`/buddies/${element.dataset.userId}`, 'POST');
    console.log(result);
    return true;
  }
  return false;
}

//////////////////////////////////////////////////////////////////////////////////////////////
//
// Examples
//
//////////////////////////////////////////////////////////////////////////////////////////////

/** demo of uhtml templates */
export function uhtml_demo() {
  const main = document.querySelector('main');
  /** render demo examples on page */
  function show_demo(name, template) {
    console.log(name, template);
    const elt = document.createElement('div');
    main.appendChild(elt);
    render(
      elt,
      html`<h3>${name}</h3>
                ${template}`
    );
    return elt;
  }

  // uhtml example 1
  const unsafe_data = '<script>alert()</script>';
  // safely inserted as a string
  const simple_tmpl = html`<em>${unsafe_data}</em>`;
  show_demo('Unsafe data (simple_tmpl)', simple_tmpl);

  // uhtml example 2
  const username = 'foo',
    nested = 'nested';
  const user = html`<em>${username}</em>`;
  // nested templates are inserted as HTML elements
  const message_tmpl = html`<div>Hello, my name is ${user}, and your name is ${html`<b>${nested}</b>`}</div>`;
  show_demo('Nested templates (message_tmpl)', message_tmpl);

  // uhtml example 3
  const users = ['alice', 'bob'];
  // you can also use lists
  const users_tmpl = html`<ul>
        ${users.map((user) => html`<li>${user}</li>`)}
    </ul>`;
  const users_elt = show_demo('Template with list (users_tmpl)', users_tmpl);
  users_elt.addEventListener('click', () => {
    users.push('eve');
    render(
      users_elt,
      html`<ul>
                ${users.map((user) => html`<li>${user}</li>`)}
            </ul>`
    );
  });

  // uhtml example 4
  const color = 'red';
  // attributes require special care
  const attr_tmpl = html`<div class="color-sample" style="${'background:' + color}"></div>`;
  show_demo('Template with attributes (attr_tmpl)', attr_tmpl);

  // uhtml example 5
  // this won't work
  const attr_tmpl_err = html`<div class="color-sample" style="background: ${color}"></div>`;
  try {
    show_demo("This shouldn't work (attr_tmpl_err)", attr_tmpl_err);
  } catch (e) {
    console.error(e);
  }
}

window.uhtml_demo = uhtml_demo;

// example of how to create elements manually
export function createElement_demo() {
  const main = document.querySelector('main');

  function element(tag, { cssClass, child } = {}) {
    const elt = document.createElement(tag);
    if (cssClass) elt.className = cssClass;
    if (typeof child === 'string' || typeof child === 'number') elt.innerText = `${child}`;
    else if (child) elt.appendChild(text);
    return elt;
  }

  const fields = [
    { key: 'Name', value: 'alice' },
    { key: 'Favourite color', value: 'pink' },
  ];
  const outerDiv = element('ul', { cssClass: 'data' });
  fields.forEach((field) => {
    const item = element('li', { cssClass: 'field' });
    item.appendChild(element('span', { cssClass: 'key', child: field.key }));
    item.appendChild(element('span', { cssClass: 'value', child: field.value }));
    outerDiv.appendChild(item);
  });
  main.appendChild(element('h3', { child: 'createElement demo' }));
  main.appendChild(outerDiv);
}
window.createElement_demo = createElement_demo;

//////////////////////////////////////////////////////////////////////////////////////////////
//
// Utility functions – you don't need to check these for vulnerabilities!
//
//////////////////////////////////////////////////////////////////////////////////////////////

/**
 * Wrapper around fetch() for JSON data
 *
 * @param {*} path The path (or URL)
 * @param {*} method Request method, defaults to GET
 * @param {*} headers Additional headers
 * @returns The response data, as an object, or null if the request failed
 */
export async function fetch_json(path, method = 'GET', headers = {}) {
  const resp = await fetch(path, {
    method,
    headers: {
      accept: 'application/json',
      ...headers,
    },
  });
  if (resp.ok) {
    const result = await resp.json();
    console.debug('Fetch result:', result);
    return result;
  } else {
    // did we get a JSON-encoded error message?
    if (resp.headers.get('content-type').startsWith('application/json')) {
      const result = await resp.json();
      console.error('Request failed:', result);
      const err = result.error;
      if (err) {
        const flash_inner = flashes.show_flash(`${err.code} ${err.name}`, 'error');
        if (err.exception === 'CSRFError') {
          const link = document.createElement('a');
          link.innerText = `${err.exception}: ${err.description}`;
          link.href =
            'https://git.app.uib.no/inf226/25h/inf226-25h/-/wikis/lectures/Cross-site,-same-site,-origins-and-cookies#csrf-token';
          link.target = '_blank';
          flash_inner.appendChild(document.createElement('br'));
          flash_inner.appendChild(link);
        }
      }
    } else {
      show_flash(`${resp.status} ${resp.statusText}`);
      console.error('Request failed:', resp.status, resp.statusText);
    }
    return null;
  }
}

/**
 * Get list of users from server
 *
 * @returns A list of simple user objects (only id and username)
 */
export async function list_users() {
  return (await fetch_json('/users/')) || [];
}

/**
 * Get a user profile from the server
 * @param {*} userid The numeric user id
 * @returns A user object
 */
export async function get_profile(userid) {
  const defaults = { name: '?', birthdate: '?', color: 'none', picture_url: './static/unknown.png', about: '' };
  const user = await fetch_json(`/users/${userid}`);
  // by setting fields to default values, we can tell the difference between a loaded profile and
  // the minimal one we get from list_users(), where everything except id and username is undefined.
  return { ...defaults, ...user };
}
