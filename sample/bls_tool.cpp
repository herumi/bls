#include <bls.hpp>
#include <iostream>
#include <cybozu/option.hpp>

template<class T>
void write(const T& t)
{
	std::cout << std::hex << std::showbase << t << std::endl;
}

template<class T>
void read(T& t)
{
	if (!(std::cin >> t)) {
		throw std::runtime_error("can't read");
	}
}

void strip(std::string& str)
{
	if (str.empty()) return;
	if (str[str.size() - 1] == '\n') str.resize(str.size() - 1);
}

void readLine(std::string& str)
{
	str.clear();
	// retry once if blank line exists
	for (size_t i = 0; i < 2; i++) {
		std::getline(std::cin, str);
		strip(str);
		if (!str.empty()) return;
	}
	throw std::runtime_error("readLine:message is empty");
}

void init()
{
	bls::SecretKey sec;
	sec.init();
	write(sec);
}

void pubkey()
{
	bls::SecretKey sec;
	read(sec);
	bls::PublicKey pub;
	sec.getPublicKey(pub);
	write(pub);
}

void sign()
{
	bls::SecretKey sec;
	read(sec);
	std::string m;
	readLine(m);
	fprintf(stderr, "sign `%s`\n", m.c_str());
	bls::Sign s;
	sec.sign(s, m);
	write(s);
}

void verify()
{
	bls::Sign s;
	read(s);
	bls::PublicKey pub;
	read(pub);
	std::string m;
	readLine(m);
	fprintf(stderr, "verify `%s`\n", m.c_str());
	bool b = s.verify(pub, m);
	write(b ? "1" : "0");
}

void share_pub()
{
	size_t k;
	read(k);
	bls::PublicKeyVec mpk(k);
	for (size_t i = 0; i < k; i++) {
		read(mpk[i]);
	}
	bls::Id id;
	read(id);
	bls::PublicKey pub;
	pub.set(mpk, id);
	write(pub);
}

void recover_sig()
{
	size_t k;
	read(k);
	bls::SecretKeyVec msk(k);
	bls::IdVec idVec(k);
	for (size_t i = 0; i < k; i++) {
		read(idVec[i]);
		read(msk[i]);
	}
	bls::SecretKey sec;
	sec.recover(msk, idVec);
	write(sec);
}

void aggregate_pub()
{
	size_t n;
	read(n);
	if (n == 0) throw std::runtime_error("aggregate_pub:n is zero");
	bls::PublicKey pub;
	read(pub);
	for (size_t i = 1; i < n; i++) {
		bls::PublicKey rhs;
		read(rhs);
		pub.add(rhs);
	}
	write(pub);
}

void aggregate_sig()
{
	size_t n;
	read(n);
	if (n == 0) throw std::runtime_error("aggregate_sig:n is zero");
	bls::Sign s;
	read(s);
	for (size_t i = 1; i < n; i++) {
		bls::Sign rhs;
		read(rhs);
		s.add(rhs);
	}
	write(s);
}

int main(int argc, char *argv[])
	try
{
	const struct CmdTbl {
		const char *name;
		void (*exec)();
	} tbl[] = {
		{ "init", init },
		{ "pubkey", pubkey },
		{ "sign", sign },
		{ "verify", verify },
		{ "share-pub", share_pub },
		{ "recover-sig", recover_sig },
		{ "aggregate-pub", aggregate_pub },
		{ "aggregate-sig", aggregate_sig },
	};
	std::string cmdCat;
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		if (i > 0) cmdCat += '|';
		cmdCat += tbl[i].name;
	}
	std::string mode;
	cybozu::Option opt;
	
	opt.appendParam(&mode, cmdCat.c_str());
	opt.appendHelp("h");
	if (!opt.parse(argc, argv)) {
		goto ERR_EXIT;
	}

	bls::init();
	for (size_t i = 0; i < CYBOZU_NUM_OF_ARRAY(tbl); i++) {
		if (mode == tbl[i].name) {
			tbl[i].exec();
			return 0;
		}
	}
	fprintf(stderr, "bad mode %s\n", mode.c_str());
ERR_EXIT:
	opt.usage();
	return 1;
} catch (std::exception& e) {
	fprintf(stderr, "ERR %s\n", e.what());
	return 1;
}
