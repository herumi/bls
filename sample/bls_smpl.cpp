#include <bls.hpp>
#include <cybozu/option.hpp>
#include <cybozu/itoa.hpp>
#include <fstream>

typedef std::vector<int> IntVec;

const std::string pubFile = "sample/publickey";
const std::string prvFile = "sample/privatekey";
const std::string signFile = "sample/sign";

std::string makeName(const std::string& name, int id)
{
	const std::string suf = ".txt";
	if (id == 0) return name + suf;
	return name + cybozu::itoa(id) + suf;
}

template<class T>
void save(const std::string& file, const T& t, int id = 0)
{
	const std::string name = makeName(file, id);
	std::ofstream ofs(name.c_str(), std::ios::binary);
	if (!(ofs << t)) {
		throw cybozu::Exception("can't save") << name;
	}
}

template<class T>
void load(T& t, const std::string& file, int id = 0)
{
	const std::string name = makeName(file, id);
	std::ifstream ifs(name.c_str(), std::ios::binary);
	if (!(ifs >> t)) {
		throw cybozu::Exception("can't load") << name;
	}
}

int init()
{
	printf("make %s and %s files\n", prvFile.c_str(), pubFile.c_str());
	bls::PrivateKey prv;
	prv.init();
	save(prvFile, prv);
	bls::PublicKey pub;
	prv.getPublicKey(pub);
	save(pubFile, pub);
	return 0;
}

int sign(const std::string& m, int id)
{
	printf("sign message `%s` by id=%d\n", m.c_str(), id);
	bls::PrivateKey prv;
	load(prv, prvFile, id);
	bls::Sign s;
	prv.sign(s, m);
	save(signFile, s, id);
	return 0;
}

int verify(const std::string& m, int id)
{
	printf("verify message `%s` by id=%d\n", m.c_str(), id);
	bls::PublicKey pub;
	load(pub, pubFile, id);
	bls::Sign s;
	load(s, signFile, id);
	if (s.verify(pub, m)) {
		puts("verify ok");
		return 0;
	} else {
		puts("verify err");
		return 1;
	}
}

int share(int n, int k)
{
	printf("%d-out-of-%d threshold sharing\n", k, n);
	bls::PrivateKey prv;
	load(prv, prvFile);
	bls::PrivateKeyVec msk;
	prv.getMasterPrivateKey(msk, k);
	std::vector<bls::PrivateKey> prvVec(n);
	for (int i = 0; i < n; i++) {
		prvVec[i].set(msk, i + 1);
	}
	for (int i = 0; i < n; i++) {
		int id = prvVec[i].getId();
		save(prvFile, prvVec[i], id);
		bls::PublicKey pub;
		prvVec[i].getPublicKey(pub);
		save(pubFile, pub, id);
	}
	return 0;
}

int recover(const IntVec& ids)
{
	printf("recover from");
	for (size_t i = 0; i < ids.size(); i++) {
		printf(" %d", ids[i]);
	}
	printf("\n");
	std::vector<bls::Sign> signVec(ids.size());
	for (size_t i = 0; i < signVec.size(); i++) {
		load(signVec[i], signFile, ids[i]);
	}
	bls::Sign s;
	s.recover(signVec);
	save(signFile, s);
	return 0;
}

int main(int argc, char *argv[])
	try
{
	std::string mode;
	std::string m;
	int n;
	int k;
	int id;
	IntVec ids;

	cybozu::Option opt;
	opt.appendParam(&mode, "init|sign|verify|share|recover");
	opt.appendOpt(&n, 10, "n", ": k-out-of-n threshold");
	opt.appendOpt(&k, 3, "k", ": k-out-of-n threshold");
	opt.appendOpt(&m, "", "m", ": message to be signed");
	opt.appendOpt(&id, 0, "id", ": id of privateKey");
	opt.appendVec(&ids, "ids", ": select k id in [0, n). this option should be last");
	opt.appendHelp("h");
	if (!opt.parse(argc, argv)) {
		goto ERR_EXIT;
	}

	bls::init();

	if (mode == "init") {
		return init();
	} else if (mode == "sign") {
		if (m.empty()) goto ERR_EXIT;
		return sign(m, id);
	} else if (mode == "verify") {
		if (m.empty()) goto ERR_EXIT;
		return verify(m, id);
	} else if (mode == "share") {
		return share(n, k);
	} else if (mode == "recover") {
		if (ids.empty()) {
			fprintf(stderr, "use -ids option. ex. share -ids 1 3 5\n");
			goto ERR_EXIT;
		}
		return recover(ids);
	} else {
		fprintf(stderr, "bad mode %s\n", mode.c_str());
	}
ERR_EXIT:
	opt.usage();
	return 1;
} catch (std::exception& e) {
	fprintf(stderr, "ERR %s\n", e.what());
	return 1;
}
