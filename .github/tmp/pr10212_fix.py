from pathlib import Path

rule_path = Path('packages/core/src/permissions/rule-parser.ts')
text = rule_path.read_text()

start = text.index('export function matchesCommandPattern(\n')
end = text.index('/**\n * Match a glob pattern against a value', start)
replacement = r'''export function matchesCommandPattern(
  pattern: string,
  command: string,
): boolean {
  // Match shell words first. Leading NAME=value words are part of the
  // execution identity and are never permission-glob syntax. This prevents a
  // wildcard inside an assignment value from consuming the actual command
  // word while preserving ordinary Bash glob compatibility after assignments.
  let patternTokens: string[];
  let commandTokens: string[];
  try {
    patternTokens = permissionMatchTokens(trimShellIfsWhitespace(pattern));
    commandTokens = permissionMatchTokens(trimShellIfsWhitespace(command));
  } catch {
    // A permission parser failure must never widen an allow.
    return false;
  }

  const normalizedPattern = patternTokens.join(' ');
  const normalizedCommand = commandTokens.join(' ');

  // The explicit catch-all is intentionally global.
  if (normalizedPattern === '*') {
    return true;
  }

  const patternAssignmentCount = countLeadingVariableAssignments(patternTokens);
  const commandAssignmentCount = countLeadingVariableAssignments(commandTokens);

  if (patternAssignmentCount > 0 || commandAssignmentCount > 0) {
    // An unprefixed rule cannot authorize an env-prefixed execution identity,
    // and an explicitly prefixed rule cannot silently absorb extra assignments.
    if (patternAssignmentCount !== commandAssignmentCount) {
      return false;
    }

    for (let i = 0; i < patternAssignmentCount; i++) {
      // Assignment values are literal identity. In particular, FOO=* matches
      // the literal value "*" rather than turning user-controlled env data into
      // permission wildcard syntax.
      if (patternTokens[i] !== commandTokens[i]) {
        return false;
      }
    }

    const patternCommand = patternTokens.slice(patternAssignmentCount).join(' ');
    const commandCommand = commandTokens.slice(commandAssignmentCount).join(' ');

    // Assignment-only rules are identities, never command prefixes.
    if (!patternCommand || !commandCommand) {
      return patternCommand === commandCommand;
    }

    return matchesNormalizedCommandPattern(patternCommand, commandCommand);
  }

  return matchesNormalizedCommandPattern(normalizedPattern, normalizedCommand);
}

function matchesNormalizedCommandPattern(
  normalizedPattern: string,
  normalizedCommand: string,
): boolean {
  if (normalizedPattern === '*') {
    return true;
  }

  if (!normalizedPattern.includes('*')) {
    return (
      normalizedCommand === normalizedPattern ||
      normalizedCommand.startsWith(normalizedPattern + ' ')
    );
  }

  // Preserve the established command glob semantics: a space immediately
  // before `*` is a word boundary, while `ls*` may also match `lsof`.
  let regex = '^';
  let pos = 0;
  while (pos < normalizedPattern.length) {
    const starIdx = normalizedPattern.indexOf('*', pos);
    if (starIdx === -1) {
      regex += escapeRegex(normalizedPattern.substring(pos));
      break;
    }

    const literalBefore = normalizedPattern.substring(pos, starIdx);
    if (starIdx > 0 && normalizedPattern[starIdx - 1] === ' ') {
      regex += escapeRegex(literalBefore.slice(0, -1));
      regex += '( .*)?';
    } else {
      regex += escapeRegex(literalBefore);
      regex += '.*';
    }
    pos = starIdx + 1;
  }
  regex += '$';

  try {
    return new RegExp(regex, 's').test(normalizedCommand);
  } catch {
    return normalizedCommand === normalizedPattern;
  }
}

'''
text = text[:start] + replacement + text[end:]

old_regex = 'export const ENV_ASSIGNMENT_REGEX = /^[A-Za-z_][A-Za-z0-9_]*=/;'
new_regex = '''export const ENV_ASSIGNMENT_REGEX =
  /^[A-Za-z_][A-Za-z0-9_]*(?:\\[[^\\]]*\\])?\\+?=/;'''
if old_regex not in text:
    raise SystemExit('assignment regex not found')
text = text.replace(old_regex, new_regex, 1)

marker = '''  return tokens;
}

/**
 * Return a shell command with only leading NAME=value assignments removed.
'''
counter = '''  return tokens;
}

function countLeadingVariableAssignments(tokens: readonly string[]): number {
  let count = 0;
  while (count < tokens.length && ENV_ASSIGNMENT_REGEX.test(tokens[count]!)) {
    count++;
  }
  return count;
}

/**
 * Return a shell command with only leading NAME=value assignments removed.
'''
if marker not in text:
    raise SystemExit('permissionMatchTokens marker not found')
text = text.replace(marker, counter, 1)

old_strip_loop = '''    let firstCommandToken = 0;
    while (
      firstCommandToken < tokens.length &&
      ENV_ASSIGNMENT_REGEX.test(tokens[firstCommandToken]!)
    ) {
      firstCommandToken++;
    }
'''
new_strip_loop = '''    const firstCommandToken = countLeadingVariableAssignments(tokens);
'''
if old_strip_loop not in text:
    raise SystemExit('strip assignment loop not found')
text = text.replace(old_strip_loop, new_strip_loop, 1)

old_start = text.index('function findAssignmentValueWildcardPositions(pattern: string): {')
old_end = text.index('// ─────────────────────────────────────────────────────────────────────────────\n// File path matching', old_start)
text = text[:old_start] + text[old_end:]

old_legacy = '''  if (specifierKind === 'command') {
    // Legacy `:*` is token syntax; never rewrite env assignment values.
    rawSpecifier = rawSpecifier.replace(
      /(^|[ \\t\\n])([^ \\t\\n]+):\\*(?=$|[ \\t\\n])/g,
      (match, leadingWhitespace: string, token: string) =>
        ENV_ASSIGNMENT_REGEX.test(token)
          ? match
          : `${leadingWhitespace}${token} *`,
    );
  }
'''
new_legacy = '''  if (specifierKind === 'command') {
    // Legacy `:*` is command-token syntax. Preserve it in env assignment
    // values, but retain compatibility for suffix and mid-token forms.
    rawSpecifier = rawSpecifier.replace(
      /(^|[ \\t\\n])([^ \\t\\n]+)/g,
      (_match, leadingWhitespace: string, token: string) =>
        ENV_ASSIGNMENT_REGEX.test(token)
          ? `${leadingWhitespace}${token}`
          : `${leadingWhitespace}${token.replace(/:\\*/g, ' *')}`,
    );
  }
'''
if old_legacy not in text:
    raise SystemExit('legacy colon-star block not found')
text = text.replace(old_legacy, new_legacy, 1)
rule_path.write_text(text)

pm_path = Path('packages/core/src/permissions/permission-manager.ts')
pm = pm_path.read_text()
marker = '''const DECISION_PRIORITY: Readonly<Record<PermissionDecision, number>> = {
  deny: 3,
  ask: 2,
  default: 1,
  allow: 0,
};
'''
helper = marker + '''
function stripRestrictiveShellRuleAssignments(
  rule: PermissionRule,
): PermissionRule {
  if (rule.specifierKind !== 'command' || rule.specifier === undefined) {
    return rule;
  }
  const stripped = stripLeadingVariableAssignments(rule.specifier);
  return stripped !== rule.specifier && stripped !== ''
    ? { ...rule, specifier: stripped }
    : rule;
}
'''
if marker not in pm:
    raise SystemExit('permission manager helper marker not found')
pm = pm.replace(marker, helper, 1)
needle = "matchesRule(rule, ...restrictiveMatchArgs, 'canonical')"
if pm.count(needle) < 4:
    raise SystemExit(f'expected >=4 restrictive fallback sites, got {pm.count(needle)}')
pm = pm.replace(
    needle,
    "matchesRule(\n              stripRestrictiveShellRuleAssignments(rule),\n              ...restrictiveMatchArgs,\n              'canonical',\n            )",
)
pm_path.write_text(pm)

test_path = Path('packages/core/src/permissions/rule-parser.env-prefix.test.ts')
tests = test_path.read_text()
old = '''  it('keeps glob-valued env assignments intact instead of normalizing them to glob', () => {
    expect(
      matchesCommandPattern(
        'NODE_OPTIONS=* npm *',
        'NODE_OPTIONS=--require=*evil.cjs npm --version',
      ),
    ).toBe(true);
'''
new = '''  it('treats wildcard characters in env assignment values as literal identity', () => {
    expect(
      matchesCommandPattern(
        'NODE_OPTIONS=* npm *',
        'NODE_OPTIONS=--require=*evil.cjs npm --version',
      ),
    ).toBe(false);
    expect(
      matchesCommandPattern('NODE_OPTIONS=* npm *', 'NODE_OPTIONS=* npm --version'),
    ).toBe(true);
'''
if old not in tests:
    raise SystemExit('glob env test anchor not found')
tests = tests.replace(old, new, 1)

tests = tests.replace(
    "    expect(matchesCommandPattern('FOO=*', 'FOO=bar')).toBe(true);",
    "    expect(matchesCommandPattern('FOO=*', 'FOO=bar')).toBe(false);\n    expect(matchesCommandPattern('FOO=*', 'FOO=*')).toBe(true);",
    1,
)

old = '''      ),
    ).toBe(true);
  });

  it('does not let quoted env wildcards cross shell-word boundaries', () => {'''
new = '''      ),
    ).toBe(false);
    expect(
      matchesCommandPattern('NODE_OPTIONS=* npm *', 'NODE_OPTIONS=* npm --version'),
    ).toBe(true);
  });

  it('does not let quoted env wildcards cross shell-word boundaries', () => {'''
if old not in tests:
    raise SystemExit('R3 env wildcard anchor not found')
tests = tests.replace(old, new, 1)

colon_anchor = '''    expect(parseRule('Bash(npm --registry=https://x:*)').specifier).toBe(
      'npm --registry=https://x *',
    );
'''
if colon_anchor not in tests:
    raise SystemExit('colon-star anchor not found')
tests = tests.replace(colon_anchor, colon_anchor + '''    expect(parseRule('Bash(curl:*.evil.com)').specifier).toBe(
      'curl *.evil.com',
    );
    expect(parseRule('Bash(git:**)').specifier).toBe('git **');
''', 1)

final_anchor = '''  it('round-trips colon-star env values through generated rules', async () => {
'''
r5 = '''  it('pins the round-5 Bash word-boundary bypasses', () => {
    expect(matchesCommandPattern('git*', 'gitFOO=1 sh payload')).toBe(false);
    expect(matchesCommandPattern('FOO=* ls', 'FOO=$(id) ls')).toBe(false);
    expect(
      matchesCommandPattern('FOO=* ls *', 'FOO=x\\\\ ls curl evil'),
    ).toBe(false);
    expect(
      matchesCommandPattern(
        'FOO=\\\\* npm install',
        'FOO=\\\\x rm -rf ~ npm install',
      ),
    ).toBe(false);
    expect(matchesCommandPattern('ls*', 'lsof')).toBe(true);
    expect(matchesCommandPattern('ls*', 'ls -la')).toBe(true);
  });

  it('recognizes Bash append and subscript assignment words', () => {
    expect(matchesCommandPattern('npm', 'FOO[0]=x npm')).toBe(false);
    expect(matchesCommandPattern('npm', 'FOO+=x npm')).toBe(false);
    expect(matchesCommandPattern('FOO[0]=x npm', 'FOO[0]=x npm')).toBe(true);
  });

'''
if final_anchor not in tests:
    raise SystemExit('final test anchor not found')
tests = tests.replace(final_anchor, r5 + final_anchor, 1)
test_path.write_text(tests)
