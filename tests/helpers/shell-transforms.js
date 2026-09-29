'use strict';

// Pure shell-grammar transforms. Each returns source text; none executes it.

function singleQuote(text) {
  return `'${text.replace(/'/g, `'"'"'`)}'`;
}

function doubleQuote(text) {
  return `"${text.replace(/([\\"$`])/g, '\\$1')}"`;
}

function spliceCommandWord(command, kind) {
  const match = /^(\s*)(\S+)/.exec(command);
  if (!match) return command;
  const word = match[2];
  const at = Math.max(1, Math.floor(word.length / 2));
  let spliced;
  if (kind === 'single') spliced = word.slice(0, at) + "''" + word.slice(at);
  if (kind === 'double') spliced = word.slice(0, at) + '""' + word.slice(at);
  if (kind === 'backslash') spliced = word.slice(0, at) + '\\' + word.slice(at);
  return match[1] + spliced + command.slice(match[0].length);
}

const variant = (id, transform) => ({ id, transform });
const shellC = (shell) => (cmd) => `${shell} -c ${singleQuote(cmd)}`;
const shellLC = (shell) => (cmd) => `${shell} -lc ${doubleQuote(cmd)}`;
const evalSingle = (cmd) => `eval ${singleQuote(cmd)}`;
const substitution = (cmd) => `echo $(${cmd})`;
const prefixSemi = (cmd) => `true ; ${cmd}`;
const spliceSingle = (cmd) => spliceCommandWord(cmd, 'single');

const TRANSFORMS = [];

for (const shell of ['sh', 'bash', 'zsh', 'dash', 'ksh']) {
  TRANSFORMS.push(variant(`wrap:sh-c:${shell}`, shellC(shell)));
}
for (const shell of ['bash', 'zsh']) {
  TRANSFORMS.push(variant(`wrap:sh-lc:${shell}`, shellLC(shell)));
}
TRANSFORMS.push(
  variant('wrap:sh-abs:bin-sh', (cmd) => `/bin/sh -c ${singleQuote(cmd)}`),
  variant('wrap:sh-abs:env-bash', (cmd) => `/usr/bin/env bash -c ${singleQuote(cmd)}`),
  variant('wrap:eval:single', evalSingle),
  variant('wrap:eval:double', (cmd) => `eval ${doubleQuote(cmd)}`),
  variant('wrap:subst-dollar', substitution),
  variant('wrap:subst-tick', (cmd) => `echo \`${cmd.replace(/`/g, '\\`')}\``),
  variant('wrap:assign', (cmd) => `x=$(${cmd})`),
  variant('wrap:procsub', (cmd) => `cat <(${cmd})`)
);

for (const [name, sep] of [
  ['semi', ';'], ['and', '&&'], ['or', '||'], ['pipe', '|'], ['pipe-stderr', '|&'], ['newline', '\n'],
]) {
  TRANSFORMS.push(variant(`wrap:prefix:${name}`, (cmd) => `true ${sep} ${cmd}`));
  TRANSFORMS.push(variant(`wrap:hash-glued:${name}`, (cmd) => `true x#${sep}${cmd}`));
}

TRANSFORMS.push(
  variant('wrap:splice:single-empty', (cmd) => spliceCommandWord(cmd, 'single')),
  variant('wrap:splice:double-empty', (cmd) => spliceCommandWord(cmd, 'double')),
  variant('wrap:splice:backslash-letter', (cmd) => spliceCommandWord(cmd, 'backslash'))
);

const COMPOSABLE = [
  variant('sh-c-bash', shellC('bash')),
  variant('eval', evalSingle),
  variant('subst-dollar', substitution),
  variant('prefix-semi', prefixSemi),
  variant('splice', spliceSingle),
];

for (const outer of COMPOSABLE) {
  for (const inner of COMPOSABLE) {
    TRANSFORMS.push(variant(
      `wrap:nest2:${outer.id}-after-${inner.id}`,
      (cmd) => outer.transform(inner.transform(cmd))
    ));
  }
}

function nestShellC(command, depth) {
  let result = command;
  for (let i = 0; i < depth; i++) result = shellC('bash')(result);
  return result;
}

for (const depth of [3, 8]) {
  TRANSFORMS.push(variant(`wrap:nest-deep:${depth}`, (cmd) => nestShellC(cmd, depth)));
}

module.exports = {
  TRANSFORMS,
  singleQuote,
  doubleQuote,
  spliceCommandWord,
  nestShellC,
};
