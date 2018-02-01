#!/bin/bash

# 'A' + (cc - 'A' + 7) % 26
export LC_CTYPE=C

encrypt_once() {

	if [[ $1 =~ [^A-Za-z] ]] ; then
		echo -n $1;
		return;
	fi;

	alphaX=$(printf '%d' "'$1");
	alphaA=$(printf '%d' "'a");

	if [ $alphaA -gt $alphaX ]; then
		alphaA=$(printf '%d' "'A");
	fi;

	ascii=$(($alphaA + ( $alphaX - $alphaA + 26 - 13) % 26))
	echo -e -n $(printf "\\\\x%x" $ascii)
}

encrypt_domain() {
	DOMAIN=$1
	XDOMAIN=""

	n=0
	while [ $n -lt ${#DOMAIN} ]; do
		c=${DOMAIN:$n:1};
		n=$(($n + 1))
		XDOMAIN=$XDOMAIN$(encrypt_once $c)
	done;

	echo -n $XDOMAIN
}

load_func() {

cat << EOF

decrypt_once() {

	if [[ \$1 =~ [^A-Za-z] ]] ; then
		echo -n \$1;
		return;
	fi;

	alphaX=\$(printf '%d' "'\$1");
	alphaA=\$(printf '%d' "'a");

	if [ \$alphaA -gt \$alphaX ]; then
		alphaA=\$(printf '%d' "'A");
	fi;

	ascii=\$((\$alphaA + ( \$alphaX - \$alphaA + 13) % 26))
	echo -e -n \$(printf "\\\\\\\\x%x" \$ascii)
}

NEED_DECRYPT=0

check_domain() {
	DOMAIN=\$1
	SUFFIX=.p.yrli.bid

	NEED_DECRYPT=0;
	if [[ \$DOMAIN =~ .*\\.p\\.yrli\\.bid ]]; then
		NEED_DECRYPT=1;
	else
		return;
	fi;
}

decrypt_domain() {
	DOMAIN=\$1
	XDOMAIN=""
	SUFFIX=.p.yrli.bid

	if ! [[ \$DOMAIN =~ .*\\.p\\.yrli\\.bid ]]; then
		echo -n \$DOMAIN;
		return;
	fi;

	n=0
	l=\${#DOMAIN} 
	k=\${#SUFFIX}
	m=\$((\$l - \$k))
	while [ \$n -lt \$m ]; do
		c=\${DOMAIN:\$n:1};
		n=\$((\$n + 1))
		XDOMAIN=\$XDOMAIN\$(decrypt_once \$c)
	done;

	echo -n \$XDOMAIN
}

decrypt_address() {
	SPLIT="";
	ADDRESS=\$1

	if [ \$NEED_DECRYPT -eq 0 ]; then
		echo -n \$ADDRESS;
		return;
	fi;

	for num in \$(echo \$ADDRESS|sed "s/\./ /g"); do
		echo -n \$SPLIT\$((\$num ^ 0x5a));
		SPLIT='.'
	done;
}

EOF
}

WRAPDOMAIN=$(encrypt_domain $1)
shift
echo $WRAPDOMAIN
nslookup $WRAPDOMAIN.p.yrli.bid $@|( sed "/Server/{N; p; d;}; s/Name:\(.*\)/Name: \$(decrypt_domain \1)/; s/Address:\(.*\)/Address: \$(decrypt_address \1)/; ")|(load_func; sed "s/^/echo /;/decrypt_domain/{h; s/.*decrypt_domain\(.*\))/check_domain \1/p; g;}")|bash

