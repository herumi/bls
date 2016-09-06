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

void readMessage(std::string& str)
{
	str.clear();
	std::string line;
	std::getline(std::cin, line); // remove first blank line
	while (std::getline(std::cin, line)) {
		if (!str.empty()) str += '\n';
		str += line;
	}
	strip(str);
	if (!str.empty()) return;
	throw std::runtime_error("readMessage:message is empty");
}

bool g_verbose = false;

void init()
{
	if (g_verbose) fprintf(stderr, "init\n");
	bls::SecretKey sec;
	sec.init();
	write(sec);
}

void pubkey()
{
	if (g_verbose) fprintf(stderr, "pubkey\n");
	bls::SecretKey sec;
	read(sec);
	if (g_verbose) std::cerr << "sec:" << sec << std::endl;
	bls::PublicKey pub;
	sec.getPublicKey(pub);
	if (g_verbose) std::cerr << "pub:" << pub << std::endl;
	write(pub);
}

void sign()
{
	if (g_verbose) fprintf(stderr, "sign\n");
	bls::SecretKey sec;
	read(sec);
	if (g_verbose) std::cerr << "sec:" << sec << std::endl;
	std::string m;
	readMessage(m);
	if (g_verbose) fprintf(stderr, "message:`%s`\n", m.c_str());
	bls::Sign s;
	sec.sign(s, m);
	write(s);
}

void verify()
{
	if (g_verbose) fprintf(stderr, "verify\n");
	bls::Sign s;
	read(s);
	if (g_verbose) std::cerr << "sign:" << s << std::endl;
	bls::PublicKey pub;
	read(pub);
	if (g_verbose) std::cerr << "pub:" << pub << std::endl;
	std::string m;
	readMessage(m);
	if (g_verbose) fprintf(stderr, "message:`%s`\n", m.c_str());
	bool b = s.verify(pub, m);
	write(b ? "1" : "0");
}

void share_pub()
{
	if (g_verbose) fprintf(stderr, "share_pub\n");
	size_t k;
	read(k);
	if (g_verbose) fprintf(stderr, "k:%d\n", (int)k);
	bls::PublicKeyVec mpk(k);
	for (size_t i = 0; i < k; i++) {
		read(mpk[i]);
	}
	bls::Id id;
	read(id);
	if (g_verbose) std::cerr << "id:" << id << std::endl;
	bls::PublicKey pub;
	pub.set(mpk, id);
	write(pub);
}

void recover_sig()
{
	if (g_verbose) fprintf(stderr, "recover_sig\n");
	size_t k;
	read(k);
	if (g_verbose) fprintf(stderr, "k:%d\n", (int)k);
	bls::SignVec sVec(k);
	bls::IdVec idVec(k);
	for (size_t i = 0; i < k; i++) {
		read(idVec[i]);
		read(sVec[i]);
	}
	bls::Sign s;
	s.recover(sVec, idVec);
	write(s);
}

void aggregate_pub()
{
	if (g_verbose) fprintf(stderr, "aggregate_pub\n");
	size_t n;
	read(n);
	if (n == 0) throw std::runtime_error("aggregate_pub:n is zero");
	if (g_verbose) fprintf(stderr, "n:%d\n", (int)n);
	bls::PublicKey pub;
	read(pub);
	if (g_verbose) std::cerr << "pub:" << pub << std::endl;
	for (size_t i = 1; i < n; i++) {
		bls::PublicKey rhs;
		read(rhs);
		pub.add(rhs);
	}
	write(pub);
}

void aggregate_sig()
{
	if (g_verbose) fprintf(stderr, "aggregate_sig\n");
	size_t n;
	read(n);
	if (n == 0) throw std::runtime_error("aggregate_sig:n is zero");
	if (g_verbose) fprintf(stderr, "n:%d\n", (int)n);
	bls::Sign s;
	read(s);
	if (g_verbose) std::cerr << "sign:" << s << std::endl;
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
	opt.appendBoolOpt(&g_verbose, "v", ": verbose");
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
