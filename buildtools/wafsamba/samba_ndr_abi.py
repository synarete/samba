# functions for checking the NDR wire format ABI of IDL files,
# see librpc/ndr/ndr_abi.h

import os
import re

from waflib import Options, Utils, Logs, Task, Build, Errors
from waflib.TaskGen import feature, after
from wafsamba import samba_utils


def ndr_abi_parse(txt):
    '''parse the output of ndr_abi_<idl> into roots, types and samples'''
    roots = []
    types = {}
    samples = {}

    cur = None
    for line in txt.splitlines():
        if line.startswith('#'):
            continue
        line = re.sub(r'\t#.*$', '', line).rstrip()
        if line == '':
            continue

        if cur is not None:
            if line == '}':
                cur = None
                continue
            if cur[0] == 'sample':
                hexdata = re.sub(r'^\s*\[[0-9a-f]+\]', '', line)
                samples[cur[1]][1] += ''.join(hexdata.split())
            else:
                types[cur[1]]['lines'].append(line.strip())
            continue

        m = re.match(r'^root (\S+)$', line)
        if m:
            roots.append(m.group(1))
            continue

        m = re.match(r'^external (\S+)$', line)
        if m:
            types[m.group(1)] = {'header': line, 'kind': 'external', 'lines': []}
            continue

        m = re.match(r'^sample (\S+) length\(\d+\)( .+)? \{$', line)
        if m:
            cur = ('sample', m.group(1))
            # a pull or repush error is part of the ABI
            samples[cur[1]] = [(m.group(2) or '').strip(), '']
            continue

        m = re.match(r'^(\[[^\]]*\] )?(struct|union|enum|bitmap) (\S+).*\{$', line)
        if m:
            cur = ('type', m.group(3))
            types[cur[1]] = {'header': line, 'kind': m.group(2), 'lines': []}
            continue

        raise Errors.WafError('Unable to parse NDR ABI line: %s' % line)

    return roots, types, samples


def ndr_abi_type_text(t):
    if t['kind'] == 'external':
        return t['header']
    return '\n\t'.join([t['header']] + t['lines'] + ['}'])


def ndr_abi_strip_external(lines):
    '''External types are opaque here, only the samples
    show their wire format, so a rename (e.g. timespec
    to timespec_legacy) is fine as long as the samples
    don't change.'''
    return [re.sub(r'external:\S+', 'external:', l) for l in lines]


def ndr_abi_compatible_change(old, new):
    '''only new union arms, enum values or bitmap bits
    and renames of external types are allowed'''
    if old['kind'] != new['kind']:
        return False
    old_lines = ndr_abi_strip_external([old['header']] + old['lines'])
    new_lines = ndr_abi_strip_external([new['header']] + new['lines'])
    if old_lines == new_lines:
        return True
    if old['kind'] not in ['union', 'enum', 'bitmap']:
        return False
    if old_lines[0] != new_lines[0]:
        return False
    for line in old_lines[1:]:
        if line not in new_lines[1:]:
            return False
    return True


def ndr_abi_sample_diff(old, new):
    '''describe the difference between two samples'''
    old_status, old_hex = old
    new_status, new_hex = new
    old_data = bytes.fromhex(old_hex)
    new_data = bytes.fromhex(new_hex)
    msg = ''
    if old_status != new_status:
        msg += '\n\tstatus: old[%s] new[%s]' % (old_status, new_status)
    if old_data != new_data:
        ofs = 0
        while ofs < min(len(old_data), len(new_data)):
            if old_data[ofs] != new_data[ofs]:
                break
            ofs += 1
        msg += ('\n\tlength: old[%u] new[%u], first difference at offset 0x%04x'
                '\n\told[0x%04x]: %s\n\tnew[0x%04x]: %s' % (
                    len(old_data), len(new_data), ofs,
                    ofs, old_data[ofs:ofs+16].hex(' '),
                    ofs, new_data[ofs:ofs+16].hex(' ')))
    return msg


def ndr_abi_check_task(self):
    '''check if the NDR wire format ABI has changed'''
    binpath = self.inputs[0].abspath()
    abi_file = self.NDR_ABI_FILE
    name = os.path.basename(abi_file)

    env = dict(os.environ)
    libpath = [os.path.join(self.generator.bld.bldnode.abspath(), d)
               for d in ['shared', 'shared/private']]
    if env.get('LD_LIBRARY_PATH'):
        libpath.append(env['LD_LIBRARY_PATH'])
    env['LD_LIBRARY_PATH'] = ':'.join(libpath)

    try:
        new_txt = samba_utils.get_string(Utils.cmd_output([binpath], env=env))
    except Exception as e:
        raise Errors.WafError('%s failed: %s' % (binpath, e))

    new_roots, new_types, new_samples = ndr_abi_parse(new_txt)

    old_txt = samba_utils.load_file(abi_file)
    if old_txt is None:
        if not samba_utils.save_file(abi_file, new_txt, create_dir=True):
            raise Errors.WafError('Failed to save NDR ABI file "%s"' % abi_file)
        Logs.warn('Generated NDR ABI file %s' % abi_file)
        return

    old_roots, old_types, old_samples = ndr_abi_parse(old_txt)

    errors = []
    refused = []

    for r in old_roots:
        if r not in new_roots:
            msg = '%s: root %s has been removed' % (name, r)
            errors.append(msg)
            refused.append(msg)
    for r in new_roots:
        if r not in old_roots:
            errors.append('%s: root %s has been added' % (name, r))

    for t in sorted(old_types.keys()):
        if t not in new_types:
            msg = '%s: type %s has been removed:\n\t%s' % (
                name, t, ndr_abi_type_text(old_types[t]))
            errors.append(msg)
            if old_types[t]['kind'] != 'external':
                refused.append(msg)
            continue
        if old_types[t] == new_types[t]:
            continue
        msg = '%s: type %s has changed:\n\told: %s\n\tnew: %s' % (
            name, t,
            ndr_abi_type_text(old_types[t]),
            ndr_abi_type_text(new_types[t]))
        errors.append(msg)
        if not ndr_abi_compatible_change(old_types[t], new_types[t]):
            refused.append(msg)
    for t in sorted(new_types.keys()):
        if t not in old_types:
            errors.append('%s: type %s has been added:\n\t%s' % (
                name, t, ndr_abi_type_text(new_types[t])))

    for s in sorted(old_samples.keys()):
        if s not in new_samples:
            msg = '%s: sample %s has been removed' % (name, s)
            errors.append(msg)
            refused.append(msg)
            continue
        if old_samples[s] == new_samples[s]:
            continue
        msg = '%s: sample %s has changed:%s' % (
            name, s, ndr_abi_sample_diff(old_samples[s], new_samples[s]))
        errors.append(msg)
        refused.append(msg)
    for s in sorted(new_samples.keys()):
        if s not in old_samples:
            errors.append('%s: sample %s has been added' % (name, s))

    if len(errors) == 0:
        if Options.options.ABI_UPDATE and old_txt != new_txt:
            # only comments changed
            samba_utils.save_file(abi_file, new_txt)
            Logs.warn('Updated comments in NDR ABI file %s' % abi_file)
        return

    if Options.options.ABI_UPDATE and len(refused) == 0:
        for e in errors:
            Logs.warn(e)
        if not samba_utils.save_file(abi_file, new_txt):
            raise Errors.WafError('Failed to save NDR ABI file "%s"' % abi_file)
        Logs.warn('Updated NDR ABI file %s' % abi_file)
        return

    if Options.options.ABI_UPDATE:
        for e in refused:
            Logs.error(e)
        raise Errors.WafError(
            'The NDR wire format of existing types in %s changed in an '
            'incompatible way!\n'
            'Data written by older versions (e.g. other nodes in a ctdb cluster) '
            'would be misinterpreted.\n'
            'Keep the old definition (maybe under a new name, '
            'e.g. timespec_legacy) and add new types or union arms gated '
            'by the cluster level.\n'
            'If you are really sure, e.g. when dropping support for an old '
            'cluster level, edit %s by hand.\n'
            'See librpc/ndr/ndr_abi.h for more information.' % (
                name, abi_file))

    for e in errors:
        Logs.error(e)
    raise Errors.WafError(
        'The NDR wire format ABI in %s has changed!\n'
        'Structures used in databases and messaging need to be stable '
        'within a ctdb cluster.\n'
        'If this is intended (only additions or compatible extensions) '
        'rebuild with --abi-update.\n'
        'See librpc/ndr/ndr_abi.h for more information.' % abi_file)


t = Task.task_factory('ndr_abi_check', ndr_abi_check_task, color='BLUE')
t.quiet = True
# The output also depends on hand-written code in shared libraries
# (e.g. ndr_push_timespec() in libndr), which doesn't
# always trigger a relink of the binary, so we always run it,
# it only takes a few milliseconds.
t.always_run = True


@after('apply_link')
@feature('ndr_abi_check')
def ndr_abi_check(self):
    '''check that the NDR wire format matches the saved ABI file'''
    tsk = self.create_task('ndr_abi_check', self.link_task.outputs[0])
    tsk.NDR_ABI_FILE = self.ndr_abi_file
    node = self.bld.root.find_node(self.ndr_abi_file)
    if node is not None:
        tsk.inputs.append(node)


def SAMBA_NDR_ABI(bld, name, deps='', abi_directory='ABI',
                  output_dir='gen_ndr'):
    '''build ndr_abi_<name> from the output of pidl --ndr-abi
    and check its output against <abi_directory>/<name>.ndrabi'''
    binname = 'ndr_abi_%s' % name

    bld.SAMBA_BINARY(binname,
                     source='%s/ndr_%s_abi.c' % (output_dir, name),
                     deps='NDR_ABI ndr talloc %s' % deps,
                     install=False)

    if not bld.env.ABI_CHECK or bld.env.CROSS_COMPILE:
        return

    try:
        t = bld.get_tgen_by_name(binname)
    except Errors.WafError:
        # e.g. disabled in fuzzing builds
        return

    abi_file = os.path.join(bld.path.abspath(), abi_directory,
                            '%s.ndrabi' % name)
    t.features = Utils.to_list(t.features) + ['ndr_abi_check']
    t.ndr_abi_file = abi_file
Build.BuildContext.SAMBA_NDR_ABI = SAMBA_NDR_ABI
