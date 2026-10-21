###################################################
# Samba4 NDR ABI (wire format) description generator
#
# Copyright Stefan Metzmacher 2026
# released under the GNU GPL

=pod

=head1 NAME

Parse::Pidl::Samba4::NDR::ABI - NDR wire format ABI generator

=head1 DESCRIPTION

This generates a C file describing the NDR wire format of all
types marked with [ndr_abi] (directly or via the interface default),
including all types they reference, also from imported IDL files.

The generated file contains two layers:

1. A textual description of the wire layout of all
   involved types (the 'type' lines), generated from
   the NDR tree, similar to what genksyms/gendwarfksyms
   or BTF do for C types.

2. Functions that fill each root structure with deterministic
   sample values, so that the generated binary can push them
   and the resulting blobs can be compared with the ones
   stored in the ABI file. This also catches changes
   in hand-written code (e.g. ndr_push_timespec()),
   which are invisible in the IDL.

=cut

package Parse::Pidl::Samba4::NDR::ABI;
use parent Parse::Pidl::Base;

use strict;
use warnings;
use Storable qw(dclone);
use Parse::Pidl qw(fatal);
use Parse::Pidl::Typelist qw(hasType getType mapTypeName
	scalar_is_reference getTypeInterface);
use Parse::Pidl::Util qw(has_property ParseExprExt unmake_str);
use Parse::Pidl::NDR qw(GetNextLevel is_charset_array);
use Parse::Pidl::Samba4 qw(choose_header ArrayDynamicallyAllocated);
use Parse::Pidl::Samba4::Header qw(GenerateStructEnv);

use vars qw($VERSION);
$VERSION = '0.01';

# Properties without influence on the wire format
my %non_wire_properties = map { $_ => 1 } (
	"public", "noprint", "nopython", "nosize", "gensize",
	"ndr_abi", "no_ndr_abi", "helpstring",
	"in", "out", "case", "default",
	# these are already described by the levels
	"size_is", "length_is", "switch_is", "string",
	"subcontext", "subcontext_size", "compression",
	"ref", "ptr", "sptr", "unique", "relative", "relative_short",
	"ignore", "represent_as",
	# these are already described by the enum/bitmap base type
	"enum8bit", "enum16bit", "v1_enum",
	"bitmap8bit", "bitmap16bit", "bitmap32bit", "bitmap64bit",
	"switch_type",
);

my %scalar_bits = (
	"int8" => 8, "uint8" => 8,
	"int16" => 16, "uint16" => 16,
	"int1632" => 16, "uint1632" => 16,
	"int32" => 32, "uint32" => 32,
	"int3264" => 32, "uint3264" => 32,
	"hyper" => 64, "int64" => 64,
	"dlong" => 64, "udlong" => 64, "udlongr" => 64,
);

sub new($)
{
	my ($class) = @_;
	my $self = {
		res => "",
		tabs => "",
		main_types => {},
		resolved => {},
		closure => {},
		closure_order => [],
		roots => [],
		unions => [],
		union_idx => {},
	};
	bless($self, $class);
}

sub is_wire_element($)
{
	my ($e) = @_;

	return 0 if has_property($e, "skip");
	return 0 if has_property($e, "skip_noinit");
	return 1;
}

sub merged_properties($)
{
	my ($t) = @_;
	my %p = ();

	if (defined($t->{DATA}) and ref($t->{DATA}) eq "HASH" and
	    defined($t->{DATA}->{PROPERTIES})) {
		%p = %{$t->{DATA}->{PROPERTIES}};
	}
	if (defined($t->{PROPERTIES})) {
		%p = (%p, %{$t->{PROPERTIES}});
	}

	return \%p;
}

sub properties_text($)
{
	my ($props) = @_;
	my @p = ();

	foreach my $k (sort keys %{$props}) {
		next if defined($non_wire_properties{$k});
		my $v = $props->{$k};
		if (not defined($v) or $v eq "1") {
			push(@p, $k);
		} else {
			push(@p, "$k($v)");
		}
	}

	return "" if (scalar(@p) == 0);
	return "[" . join(",", @p) . "] ";
}

#####################################################################
# Find the parsed NDR representation of a type, this works
# for types of the current IDL file and for imported ones.
sub resolve($$)
{
	my ($self, $name) = @_;

	return $self->{resolved}->{$name} if defined($self->{resolved}->{$name});

	my $r = undef;
	my $t = $self->{main_types}->{$name};

	if (not defined($t) and hasType($name)) {
		my $raw = getType($name);

		if ($raw->{TYPE} eq "TYPEDEF" and ref($raw->{DATA}) eq "HASH" and
		    $raw->{DATA}->{TYPE} eq "SCALAR") {
			$r = { NAME => $name, KIND => "scalar" };
		} elsif ($raw->{TYPE} eq "TYPEDEF" and ref($raw->{DATA}) ne "HASH") {
			$r = $self->resolve($raw->{DATA});
		} else {
			# An imported type, we need to generate
			# the NDR tree on a private copy, as
			# Parse::Pidl::NDR modifies the IDL tree.
			my $iface = getTypeInterface($name);
			my $pointer_default = "unique";
			my $ms_union = 0;
			if (defined($iface)) {
				$pointer_default = has_property($iface, "pointer_default") // "unique";
				$ms_union = 1 if has_property($iface, "ms_union");
			}
			my $copy = dclone($raw);
			if ($copy->{TYPE} eq "TYPEDEF") {
				$copy->{DATA}->{PARENT} = $copy;
				$copy->{DATA}->{NAME} //= $copy->{NAME};
				foreach my $e (@{$copy->{DATA}->{ELEMENTS} // []}) {
					$e->{PARENT} = $copy->{DATA} if ref($e) eq "HASH";
				}
			}
			$t = Parse::Pidl::NDR::ParseType($copy, $pointer_default, $ms_union);
		}
	}

	if (not defined($r) and not defined($t)) {
		$r = { NAME => $name, KIND => "external" };
	}

	if (not defined($r)) {
		my $data = $t;
		$data = $t->{DATA} if ($t->{TYPE} eq "TYPEDEF");
		my $props = merged_properties($t);
		my $handwritten = (defined($props->{nopush}) or defined($props->{nopull}));
		$r = {
			NAME => $name,
			KIND => lc($data->{TYPE}),
			DATA => $data,
			PROPERTIES => $props,
			ORIGINAL => $t,
			HANDWRITTEN => $handwritten,
		};
		if ($r->{KIND} eq "struct" or $r->{KIND} eq "union") {
			fatal($t, "$name: ndr_abi does not support types without body")
				unless defined($data->{ELEMENTS});
		}
	}

	$self->{resolved}->{$name} = $r;
	return $r;
}

sub type_ref($$)
{
	my ($self, $name) = @_;

	if (ref($name) eq "HASH") {
		fatal($name, "ndr_abi does not support inline types");
	}

	my $r = $self->resolve($name);
	return "$r->{KIND}:$r->{NAME}";
}

#####################################################################
# Walk all types reachable from the roots
sub add_closure($$$)
{
	my ($self, $name, $from) = @_;

	my $r = $self->resolve($name);

	return if ($r->{KIND} eq "scalar");
	return if defined($self->{closure}->{$r->{NAME}});

	if (defined($r->{PROPERTIES}) and has_property($r, "no_ndr_abi")) {
		fatal($r->{ORIGINAL}, "$r->{NAME} is marked [no_ndr_abi], but used by [ndr_abi] type $from");
	}

	$self->{closure}->{$r->{NAME}} = $r;
	push(@{$self->{closure_order}}, $r);

	return if ($r->{KIND} eq "external");

	if ($r->{KIND} eq "union") {
		$r->{UNION_IDX} = scalar(@{$self->{unions}});
		push(@{$self->{unions}}, $r);
		my $st = $r->{DATA}->{SWITCH_TYPE};
		$self->add_closure($st, $r->{NAME}) if defined($st);
	}

	if ($r->{KIND} eq "enum" or $r->{KIND} eq "bitmap") {
		return;
	}

	foreach my $e (@{$r->{DATA}->{ELEMENTS}}) {
		next if ($e->{TYPE} eq "EMPTY");
		next unless is_wire_element($e);
		my $ignored = 0;
		foreach my $l (@{$e->{LEVELS}}) {
			$ignored = 1 if ($l->{TYPE} eq "POINTER" and
					 $l->{POINTER_TYPE} eq "ignore");
		}
		next if $ignored;
		$self->add_closure($e->{TYPE}, $r->{NAME});
	}
}

#####################################################################
# Layer A: the textual wire format description
sub element_text($$)
{
	my ($self, $e) = @_;
	my $txt = properties_text($e->{PROPERTIES} // {});

	foreach my $l (@{$e->{LEVELS}}) {
		if ($l->{TYPE} eq "POINTER") {
			$txt .= "ptr($l->{POINTER_TYPE}) ";
			# an [ignore] pointer is just a NULL pointer on the wire
			return "$txt" . "void" if ($l->{POINTER_TYPE} eq "ignore");
		} elsif ($l->{TYPE} eq "ARRAY") {
			my @a = ();
			push(@a, "fixed=$l->{SIZE_IS}") if $l->{IS_FIXED};
			push(@a, "inline=$l->{SIZE_IS}") if $l->{IS_INLINE};
			push(@a, "conformant=$l->{SIZE_IS}") if ($l->{IS_CONFORMANT} and defined($l->{SIZE_IS}));
			push(@a, "conformant") if ($l->{IS_CONFORMANT} and not defined($l->{SIZE_IS}));
			push(@a, "varying=$l->{LENGTH_IS}") if ($l->{IS_VARYING} and defined($l->{LENGTH_IS}));
			push(@a, "varying") if ($l->{IS_VARYING} and not defined($l->{LENGTH_IS}));
			push(@a, "zero_terminated") if $l->{IS_ZERO_TERMINATED};
			push(@a, "surrounding") if $l->{IS_SURROUNDING};
			push(@a, "to_null") if $l->{IS_TO_NULL};
			$txt .= "array(" . join(",", @a) . ") ";
		} elsif ($l->{TYPE} eq "SUBCONTEXT") {
			$txt .= "subcontext($l->{HEADER_SIZE},$l->{SUBCONTEXT_SIZE}";
			$txt .= ",compression=$l->{COMPRESSION}" if defined($l->{COMPRESSION});
			$txt .= ") ";
		} elsif ($l->{TYPE} eq "SWITCH") {
			$txt .= "switch($l->{SWITCH_IS}) ";
		} elsif ($l->{TYPE} eq "DATA") {
			$txt .= $self->type_ref($l->{DATA_TYPE});
		} else {
			fatal($e->{ORIGINAL}, "ndr_abi: unsupported level type $l->{TYPE}");
		}
	}

	return $txt;
}

sub align_text($)
{
	my ($r) = @_;
	my $align = $r->{DATA}->{ALIGN};
	return "" unless defined($align);
	return " align($align)";
}

sub type_text($$)
{
	my ($self, $r) = @_;
	my @lines = ();
	my $props = properties_text($r->{PROPERTIES});

	if ($r->{KIND} eq "external") {
		push(@lines, "external $r->{NAME}");
		return @lines;
	}

	if ($r->{KIND} eq "enum" or $r->{KIND} eq "bitmap") {
		my $base = $r->{DATA}->{BASE_TYPE};
		push(@lines, "$props$r->{KIND} $r->{NAME} base($base) {");
		my $next = 0;
		foreach my $x (@{$r->{DATA}->{ELEMENTS} // []}) {
			my ($n, $v) = split(/=/, $x, 2);
			$n =~ s/^\s+|\s+$//g;
			if (defined($v)) {
				$v =~ s/^\s+|\s+$//g;
			} else {
				$v = $next;
			}
			if ($v =~ /^0x[0-9A-Fa-f]+$/) {
				$next = hex($v) + 1;
			} elsif ($v =~ /^\d+$/) {
				$next = $v + 1;
			} else {
				$next = "($v)+1";
			}
			push(@lines, "\t$v\t# $n");
		}
		push(@lines, "}");
		return @lines;
	}

	if ($r->{KIND} eq "struct") {
		push(@lines, "$props" . "struct $r->{NAME}" . align_text($r) . " {");
		foreach my $e (@{$r->{DATA}->{ELEMENTS}}) {
			next unless is_wire_element($e);
			push(@lines, "\t" . $self->element_text($e) . "\t# $e->{NAME}");
		}
		push(@lines, "}");
		return @lines;
	}

	if ($r->{KIND} eq "union") {
		my $st = $r->{DATA}->{SWITCH_TYPE};
		my $sw = "";
		$sw = " switch_type(" . $self->type_ref($st) . ")" if defined($st);
		push(@lines, "$props" . "union $r->{NAME}" . align_text($r) . "$sw {");
		foreach my $e (@{$r->{DATA}->{ELEMENTS}}) {
			my $c = $e->{CASE};
			$c =~ s/^case (.*)$/case($1)/;
			if ($e->{TYPE} eq "EMPTY") {
				push(@lines, "\t$c: EMPTY");
				next;
			}
			next unless is_wire_element($e);
			push(@lines, "\t$c: " . $self->element_text($e) . "\t# $e->{NAME}");
		}
		push(@lines, "}");
		return @lines;
	}

	fatal($r->{ORIGINAL}, "ndr_abi: unsupported type kind $r->{KIND}");
}

sub types_text($)
{
	my ($self) = @_;
	my @lines = ();

	foreach my $r (@{$self->{roots}}) {
		push(@lines, "root $r->{NAME}");
	}
	push(@lines, "");

	foreach my $name (sort keys %{$self->{closure}}) {
		my $r = $self->{closure}->{$name};
		push(@lines, $self->type_text($r));
		push(@lines, "");
	}

	return join("\n", @lines);
}

#####################################################################
# Layer B: functions filling the structures with sample values

sub fill_fn_name($$)
{
	my ($self, $r) = @_;

	if ($r->{KIND} eq "external" or $r->{HANDWRITTEN}) {
		# hand-written, see librpc/ndr/ndr_abi.h
		return "ndr_abi_fill_$r->{NAME}";
	}

	return "_ndr_abi_fill_$r->{KIND}_$r->{NAME}";
}

sub c_type($$)
{
	my ($self, $r) = @_;

	return "struct $r->{NAME}" if ($r->{KIND} eq "external");
	return mapTypeName($r->{NAME});
}

sub bits_of($$)
{
	my ($self, $name) = @_;
	my $r = $self->resolve($name);

	if ($r->{KIND} eq "enum" or $r->{KIND} eq "bitmap") {
		return $self->bits_of($r->{DATA}->{BASE_TYPE});
	}

	return $scalar_bits{$name};
}

sub parse_expr($$$$)
{
	my ($self, $expr, $env, $e) = @_;
	my @used = ();

	my $c = ParseExprExt($expr, $env, $e->{ORIGINAL}, undef,
		sub { my $x = shift; push(@used, $x); return $x; });

	return ($c, \@used);
}

sub FillData($$$$$)
{
	my ($self, $e, $l, $var, $env) = @_;
	my $r = $self->resolve($l->{DATA_TYPE});
	my $range = has_property($e, "range");

	if ($r->{KIND} eq "scalar" or $r->{KIND} eq "enum" or $r->{KIND} eq "bitmap") {
		my $ctype = mapTypeName($r->{NAME});
		if (defined($range)) {
			my ($low, $high) = split(/,/, $range, 2);
			$self->pidl("$var = ($ctype)ndr_abi_range(state, $low, $high);");
		} elsif ($r->{KIND} eq "scalar") {
			$self->pidl("ndr_abi_fill_$r->{NAME}(state, &$var);");
		} else {
			my $bits = $self->bits_of($r->{NAME});
			$self->pidl("$var = ($ctype)ndr_abi_uint(state, $bits);");
		}
		return;
	}

	if ($r->{KIND} eq "union") {
		fatal($e->{ORIGINAL}, "ndr_abi: union $r->{NAME} without switch_is()");
	}

	if ($r->{KIND} eq "external" or $r->{KIND} eq "struct") {
		$self->pidl($self->fill_fn_name($r) . "(state, &$var);");
		return;
	}

	fatal($e->{ORIGINAL}, "ndr_abi: unsupported data type $r->{NAME}");
}

sub FillLevel($$$$$)
{
	my ($self, $e, $l, $var, $env) = @_;

	if ($l->{TYPE} eq "POINTER") {
		my $nl = GetNextLevel($e, $l);
		return if ($l->{POINTER_TYPE} eq "ignore");

		my $nullable = ($l->{POINTER_TYPE} ne "ref");
		if ($nullable) {
			$self->pidl("if (!state->null_pointers) {");
			$self->indent;
		}

		if ($nl->{TYPE} eq "ARRAY" or
		    ($nl->{TYPE} eq "DATA" and scalar_is_reference($nl->{DATA_TYPE}))) {
			# the pointer is shared with the array or string
			$self->FillLevel($e, $nl, $var, $env);
		} else {
			$self->pidl("$var = ndr_abi_talloc_zero(state, sizeof(*$var));");
			$self->FillLevel($e, $nl, "(*$var)", $env);
		}

		if ($nullable) {
			$self->deindent;
			$self->pidl("}");
		}
		return;
	}

	if ($l->{TYPE} eq "ARRAY") {
		my $nl = GetNextLevel($e, $l);

		if (is_charset_array($e, $l)) {
			$self->pidl("$var = ndr_abi_string(state);");
			return;
		}
		if ($l->{IS_ZERO_TERMINATED}) {
			fatal($e->{ORIGINAL}, "ndr_abi: zero terminated array without charset");
		}

		my $size;
		if ($l->{IS_FIXED}) {
			$size = $l->{SIZE_IS};
		} else {
			($size) = $self->parse_expr($l->{SIZE_IS}, $env, $e);
		}

		if (ArrayDynamicallyAllocated($e, $l)) {
			$self->pidl("$var = ndr_abi_talloc_zero_array(state, sizeof(*$var), $size);");
		}

		my $cntr = "cntr_$e->{NAME}_$l->{LEVEL_INDEX}";
		$self->pidl("{");
		$self->indent;
		$self->pidl("uint32_t $cntr;");
		$self->pidl("for ($cntr = 0; $cntr < ($size); $cntr++) {");
		$self->indent;
		$self->FillLevel($e, $nl, "$var\[$cntr\]", $env);
		$self->deindent;
		$self->pidl("}");
		$self->deindent;
		$self->pidl("}");
		return;
	}

	if ($l->{TYPE} eq "SUBCONTEXT") {
		$self->FillLevel($e, GetNextLevel($e, $l), $var, $env);
		return;
	}

	if ($l->{TYPE} eq "SWITCH") {
		my $nl = GetNextLevel($e, $l);
		my $r = $self->resolve($nl->{DATA_TYPE});
		my ($sw) = $self->parse_expr($l->{SWITCH_IS}, $env, $e);

		fatal($e->{ORIGINAL}, "ndr_abi: switch_is() on non-union $r->{NAME}")
			unless ($r->{KIND} eq "union");

		$self->pidl($self->fill_fn_name($r) . "(state, &$var, (uint64_t)($sw));");
		return;
	}

	if ($l->{TYPE} eq "DATA") {
		$self->FillData($e, $l, $var, $env);
		return;
	}

	fatal($e->{ORIGINAL}, "ndr_abi: unsupported level $l->{TYPE}");
}

sub FillElement($$$$)
{
	my ($self, $e, $var, $env) = @_;

	return unless is_wire_element($e);
	# the value is calculated by the push code
	return if defined(has_property($e, "value"));

	$self->FillLevel($e, $e->{LEVELS}[0], $var, $env);
}

sub union_level_fn($$)
{
	my ($self, $r) = @_;
	return "_ndr_abi_level_$r->{NAME}";
}

sub FillStruct($$)
{
	my ($self, $r) = @_;
	my $struct = $r->{DATA};
	my $env = GenerateStructEnv($struct, "r");
	my %siblings = map { $_->{NAME} => $_ } @{$struct->{ELEMENTS}};
	my %preset = ();
	my @preset = ();

	# First find all elements, which are used as
	# array sizes/lengths or union discriminants,
	# we need to set them before anything else.
	foreach my $e (@{$struct->{ELEMENTS}}) {
		next unless is_wire_element($e);
		foreach my $l (@{$e->{LEVELS}}) {
			if ($l->{TYPE} eq "ARRAY" and not $l->{IS_FIXED}) {
				foreach my $expr ($l->{SIZE_IS}, $l->{LENGTH_IS}) {
					next unless defined($expr);
					my (undef, $used) = $self->parse_expr($expr, {}, $e);
					foreach my $u (@{$used}) {
						$u =~ s/^\*//;
						next unless defined($siblings{$u});
						next if defined($preset{$u});
						$preset{$u} = { TYPE => "COUNT" };
						push(@preset, $u);
					}
				}
			}
			if ($l->{TYPE} eq "SWITCH") {
				my $sw = $l->{SWITCH_IS};
				my $nl = GetNextLevel($e, $l);
				my $u = $self->resolve($nl->{DATA_TYPE});
				if ($sw =~ /^\s*(\w+)\s*&\s*(.+?)\s*$/ and defined($siblings{$1})) {
					# e.g. switch_is(flags & SEC_ACE_OBJECT_TYPE_PRESENT),
					# all masked selections are combined in the sibling
					my ($s, $mask) = ($1, $2);
					if (not defined($preset{$s})) {
						$preset{$s} = { TYPE => "MASKSWITCH", MASKS => [] };
						push(@preset, $s);
					}
					fatal($e->{ORIGINAL}, "ndr_abi: $s used for more than one purpose")
						unless ($preset{$s}->{TYPE} eq "MASKSWITCH");
					push(@{$preset{$s}->{MASKS}}, { UNION => $u, MASK => $mask });
					next;
				}
				fatal($e->{ORIGINAL}, "ndr_abi: only switch_is(sibling) or switch_is(sibling & MASK) expressions are supported: '$sw'")
					unless defined($siblings{$sw});
				if (defined($preset{$sw})) {
					fatal($e->{ORIGINAL}, "ndr_abi: $sw used for more than one purpose")
						unless ($preset{$sw}->{TYPE} eq "SWITCH" and
							$preset{$sw}->{UNION} == $u);
					next;
				}
				$preset{$sw} = { TYPE => "SWITCH", UNION => $u };
				push(@preset, $sw);
			}
		}
	}

	$self->pidl("static void " . $self->fill_fn_name($r) . "(struct ndr_abi_state *state, " . $self->c_type($r) . " *r)");
	$self->pidl("{");
	$self->indent;

	foreach my $n (@preset) {
		my $p = $preset{$n};
		my $e = $siblings{$n};
		my $ctype = mapTypeName($e->{TYPE});
		fatal($e->{ORIGINAL}, "ndr_abi: $n used as size/switch, but is not a scalar")
			unless ($e->{LEVELS}[0]->{TYPE} eq "DATA");
		if ($p->{TYPE} eq "COUNT") {
			my ($low, $high) = ("0", "UINT32_MAX");
			my $range = has_property($e, "range");
			($low, $high) = split(/,/, $range, 2) if defined($range);
			$self->pidl("r->$n = ($ctype)ndr_abi_count(state, $low, $high);");
		} elsif ($p->{TYPE} eq "MASKSWITCH") {
			$self->pidl("r->$n = ($ctype)0;");
			foreach my $m (@{$p->{MASKS}}) {
				$self->pidl("r->$n = ($ctype)((uint64_t)r->$n | (" .
					$self->union_level_fn($m->{UNION}) .
					"(state) & (uint64_t)($m->{MASK})));");
			}
		} else {
			$self->pidl("r->$n = ($ctype)" . $self->union_level_fn($p->{UNION}) . "(state);");
		}
	}

	foreach my $e (@{$struct->{ELEMENTS}}) {
		next if defined($preset{$e->{NAME}});
		$self->FillElement($e, "r->$e->{NAME}", $env);
	}

	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

sub FillUnion($$)
{
	my ($self, $r) = @_;
	my $union = $r->{DATA};
	my @arms = @{$union->{ELEMENTS}};
	my @cases = ();

	foreach my $e (@arms) {
		next if ($e->{CASE} eq "default");
		my $c = $e->{CASE};
		$c =~ s/^case //;
		push(@cases, $c);
	}

	# The discriminant value for the selected arm
	$self->pidl("static uint64_t " . $self->union_level_fn($r) . "(struct ndr_abi_state *state)");
	$self->pidl("{");
	$self->indent;
	# For the default arm we use the lowest value,
	# which doesn't match any case, this also works
	# for switch_is(flags & MASK).
	$self->pidl("uint64_t v = 0;");
	$self->pidl("");
	$self->pidl("switch (state->selections[$r->{UNION_IDX}]) {");
	my $idx = 0;
	foreach my $e (@arms) {
		if ($e->{CASE} eq "default") {
			$self->pidl("case $idx: /* default */");
			$self->indent;
			$self->pidl("while (" . join(" || ", map { "v == (uint64_t)($_)" } @cases) . ") {")
				if (scalar(@cases) > 0);
			$self->pidl("\tv++;") if (scalar(@cases) > 0);
			$self->pidl("}") if (scalar(@cases) > 0);
			$self->pidl("return v;");
			$self->deindent;
		} else {
			my $c = $e->{CASE};
			$c =~ s/^case //;
			$self->pidl("case $idx:");
			$self->pidl("\treturn (uint64_t)($c);");
		}
		$idx++;
	}
	$self->pidl("}");
	$self->pidl("");
	$self->pidl("ndr_abi_invalid_selection(state, \"$r->{NAME}\");");
	$self->pidl("return v;");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");

	$self->pidl("static void " . $self->fill_fn_name($r) . "(struct ndr_abi_state *state, " . $self->c_type($r) . " *r, uint64_t level)");
	$self->pidl("{");
	$self->indent;
	my $has_default = 0;
	$self->pidl("switch (level) {");
	foreach my $e (@arms) {
		if ($e->{CASE} eq "default") {
			$self->pidl("default:");
			$has_default = 1;
		} else {
			$self->pidl("$e->{CASE}:");
		}
		$self->indent;
		if ($e->{TYPE} ne "EMPTY") {
			$self->FillElement($e, "r->$e->{NAME}", {});
		}
		$self->pidl("break;");
		$self->deindent;
	}
	if (not $has_default) {
		$self->pidl("default:");
		$self->pidl("\tndr_abi_invalid_selection(state, \"$r->{NAME}\");");
		$self->pidl("\tbreak;");
	}
	$self->pidl("}");
	$self->deindent;
	$self->pidl("}");
	$self->pidl("");
}

#####################################################################
# Calculate which unions are reachable via which arms
sub reachable_unions($$$)
{
	my ($self, $name, $seen) = @_;
	my $r = $self->resolve($name);
	my %res = ();

	return \%res unless defined($self->{closure}->{$r->{NAME}});
	return \%res if defined($seen->{$r->{NAME}});
	return \%res unless ($r->{KIND} eq "struct" or $r->{KIND} eq "union");
	return \%res if $r->{HANDWRITTEN};

	$seen->{$r->{NAME}} = 1;
	$res{$r->{NAME}} = 1 if ($r->{KIND} eq "union");

	foreach my $e (@{$r->{DATA}->{ELEMENTS}}) {
		next if ($e->{TYPE} eq "EMPTY");
		next unless is_wire_element($e);
		my $sub = $self->reachable_unions($e->{TYPE}, $seen);
		%res = (%res, %{$sub});
	}

	delete $seen->{$r->{NAME}};
	return \%res;
}

sub arm_reaches($$$)
{
	my ($self, $arm, $target) = @_;

	return 0 if ($arm->{TYPE} eq "EMPTY");
	my $sub = $self->reachable_unions($arm->{TYPE}, {});
	return defined($sub->{$target->{NAME}});
}

sub GenerateSamples($)
{
	my ($self) = @_;
	my @samples = ();
	my %sampled_unions = ();

	foreach my $root (@{$self->{roots}}) {
		next unless ($root->{KIND} eq "struct");
		next if $root->{HANDWRITTEN};

		my @base = map { 0 } @{$self->{unions}};

		# All optional pointers are set and arrays have 2 elements
		push(@samples, {
			NAME => $root->{NAME},
			ROOT => $root,
			NULL_POINTERS => 0,
			MIN_COUNTS => 0,
			SELECTIONS => [@base],
		});
		# All optional pointers are NULL and arrays are empty
		push(@samples, {
			NAME => "$root->{NAME}\@minimal",
			ROOT => $root,
			NULL_POINTERS => 1,
			MIN_COUNTS => 1,
			SELECTIONS => [@base],
		});
		# All optional pointers are set and arrays are empty
		push(@samples, {
			NAME => "$root->{NAME}\@empty_arrays",
			ROOT => $root,
			NULL_POINTERS => 0,
			MIN_COUNTS => 1,
			SELECTIONS => [@base],
		});

		my $reachable = $self->reachable_unions($root->{NAME}, {});

		foreach my $u (@{$self->{unions}}) {
			next unless defined($reachable->{$u->{NAME}});
			# The arms of each union are only sampled
			# via the first root (in IDL order) using it.
			next if defined($sampled_unions{$u->{NAME}});
			$sampled_unions{$u->{NAME}} = $root->{NAME};
			my @arms = @{$u->{DATA}->{ELEMENTS}};
			for (my $i = 1; $i <= $#arms; $i++) {
				next if ($arms[$i]->{TYPE} eq "EMPTY");
				my @sel = @base;
				$sel[$u->{UNION_IDX}] = $i;
				# Make sure the other unions select an
				# arm, which reaches the target union.
				foreach my $o (@{$self->{unions}}) {
					next if ($o == $u);
					my @oarms = @{$o->{DATA}->{ELEMENTS}};
					for (my $j = 0; $j <= $#oarms; $j++) {
						next unless $self->arm_reaches($oarms[$j], $u);
						$sel[$o->{UNION_IDX}] = $j;
						last;
					}
				}
				my $c = $arms[$i]->{CASE};
				$c =~ s/^case //;
				$c = "($c)" unless ($c eq "default");
				push(@samples, {
					NAME => "$root->{NAME}\@$u->{NAME}$c",
					ROOT => $root,
					NULL_POINTERS => 0,
					MIN_COUNTS => 0,
					SELECTIONS => \@sel,
				});
			}
		}
	}

	return @samples;
}

sub c_string($)
{
	my ($s) = @_;
	$s =~ s/\\/\\\\/g;
	$s =~ s/"/\\"/g;
	$s =~ s/\t/\\t/g;
	return "\"$s\\n\"";
}

#####################################################################
# Generate the C file
sub Parse($$$$)
{
	my ($self, $ndr, $basename, $h_filename) = @_;
	my @interfaces = ();

	foreach my $x (@{$ndr}) {
		next unless ($x->{TYPE} eq "INTERFACE");
		push(@interfaces, $x);
		foreach my $t (@{$x->{TYPES}}) {
			next unless defined($t->{NAME});
			$self->{main_types}->{$t->{NAME}} = $t;
		}
	}

	foreach my $x (@interfaces) {
		my $default = has_property($x, "ndr_abi");
		fatal($x, "$x->{NAME}: [ndr_abi] and [no_ndr_abi] can't be used together")
			if ($default and has_property($x, "no_ndr_abi"));

		foreach my $t (@{$x->{TYPES}}) {
			next unless defined($t->{NAME});
			my $props = merged_properties($t);
			my $yes = defined($props->{ndr_abi});
			my $no = defined($props->{no_ndr_abi});
			my $public = defined($props->{public});

			fatal($t, "$t->{NAME}: [ndr_abi] and [no_ndr_abi] can't be used together")
				if ($yes and $no);
			fatal($t, "$t->{NAME}: [ndr_abi] requires [public]")
				if ($yes and not $public);

			next if $no;
			next unless ($yes or ($default and $public));

			push(@{$self->{roots}}, $self->resolve($t->{NAME}));
		}
	}

	foreach my $r (@{$self->{roots}}) {
		$self->add_closure($r->{NAME}, $r->{NAME});
	}

	my $types = $self->types_text();

	$self->pidl("/* NDR ABI description auto-generated by pidl */");
	$self->pidl("");
	$self->pidl("#include \"replace.h\"");
	$self->pidl("#include \"$h_filename\"");
	foreach my $x (@{$ndr}) {
		next unless ($x->{TYPE} eq "IMPORT");
		foreach my $i (@{$x->{PATHS}}) {
			my $p = unmake_str($i);
			$p =~ s/\.idl$//;
			$self->pidl(choose_header("librpc/gen_ndr/ndr_$p\.h", "gen_ndr/ndr_$p.h"));
		}
	}
	$self->pidl(choose_header("librpc/ndr/ndr_abi.h", "ndr_abi.h"));
	$self->pidl("");

	# Types only reachable via [value()] elements
	# are part of the description, but their fill
	# functions are not used, hence _UNUSED_.
	my @generated = ();
	foreach my $r (@{$self->{closure_order}}) {
		next if ($r->{KIND} eq "external");
		next if $r->{HANDWRITTEN};
		if ($r->{KIND} eq "struct") {
			$self->pidl("static void " . $self->fill_fn_name($r) . "(struct ndr_abi_state *state, " . $self->c_type($r) . " *r) _UNUSED_;");
			push(@generated, $r);
		} elsif ($r->{KIND} eq "union") {
			$self->pidl("static uint64_t " . $self->union_level_fn($r) . "(struct ndr_abi_state *state) _UNUSED_;");
			$self->pidl("static void " . $self->fill_fn_name($r) . "(struct ndr_abi_state *state, " . $self->c_type($r) . " *r, uint64_t level) _UNUSED_;");
			push(@generated, $r);
		}
	}
	$self->pidl("");

	foreach my $r (@generated) {
		$self->FillStruct($r) if ($r->{KIND} eq "struct");
		$self->FillUnion($r) if ($r->{KIND} eq "union");
	}

	my @samples = $self->GenerateSamples();
	my $num_unions = scalar(@{$self->{unions}});

	foreach my $r (@{$self->{roots}}) {
		next unless ($r->{KIND} eq "struct");
		next if $r->{HANDWRITTEN};
		$self->pidl("static void *_ndr_abi_sample_$r->{NAME}(struct ndr_abi_state *state)");
		$self->pidl("{");
		$self->indent;
		$self->pidl($self->c_type($r) . " *r = ndr_abi_talloc_zero(state, sizeof(*r));");
		$self->pidl($self->fill_fn_name($r) . "(state, r);");
		$self->pidl("return r;");
		$self->deindent;
		$self->pidl("}");
		$self->pidl("");
	}

	my $i = 0;
	foreach my $s (@samples) {
		my @sel = @{$s->{SELECTIONS}};
		push(@sel, 0) if (scalar(@sel) == 0);
		$self->pidl("static const uint8_t _ndr_abi_selections_$i\[\] = { " . join(", ", @sel) . " };");
		$i++;
	}
	$self->pidl("");

	$self->pidl("static const struct ndr_abi_sample _ndr_abi_samples[] = {");
	$self->indent;
	$i = 0;
	foreach my $s (@samples) {
		my $n = $s->{ROOT}->{NAME};
		$self->pidl("{");
		$self->indent;
		$self->pidl(".name = \"$s->{NAME}\",");
		$self->pidl(".type_name = \"$n\",");
		$self->pidl(".null_pointers = " . ($s->{NULL_POINTERS} ? "true" : "false") . ",");
		$self->pidl(".min_counts = " . ($s->{MIN_COUNTS} ? "true" : "false") . ",");
		$self->pidl(".selections = _ndr_abi_selections_$i,");
		$self->pidl(".num_selections = $num_unions,");
		$self->pidl(".fill = _ndr_abi_sample_$n,");
		$self->pidl(".struct_size = sizeof(" . $self->c_type($s->{ROOT}) . "),");
		$self->pidl(".push = (ndr_push_flags_fn_t)ndr_push_$n,");
		$self->pidl(".pull = (ndr_pull_flags_fn_t)ndr_pull_$n,");
		$self->pidl(".print = (ndr_print_fn_t)ndr_print_$n,");
		$self->deindent;
		$self->pidl("},");
		$i++;
	}
	$self->pidl("{ .name = NULL, },");
	$self->deindent;
	$self->pidl("};");
	$self->pidl("");

	$self->pidl("static const char _ndr_abi_types[] =");
	$self->indent;
	foreach my $line (split(/\n/, $types, -1)) {
		$self->pidl(c_string($line));
	}
	$self->pidl(";");
	$self->deindent;
	$self->pidl("");

	$self->pidl("static const struct ndr_abi_table _ndr_abi_table = {");
	$self->indent;
	$self->pidl(".idl_name = \"$basename\",");
	$self->pidl(".types = _ndr_abi_types,");
	$self->pidl(".num_samples = " . scalar(@samples) . ",");
	$self->pidl(".samples = _ndr_abi_samples,");
	$self->deindent;
	$self->pidl("};");
	$self->pidl("");

	$self->pidl("int main(int argc, const char *argv[])");
	$self->pidl("{");
	$self->pidl("\treturn ndr_abi_main(&_ndr_abi_table, argc, argv);");
	$self->pidl("}");

	return $self->{res};
}

1;
