#include <bls.hpp>
#include <cybozu/option.hpp>
#include <cybozu/itoa.hpp>
#include <fstream>

typedef std::vector<int> IntVec;

const std::string pubFile = "sample/publickey";
const std::string secFile = "sample/secretkey";
const std::string signFile = "sample/sign";

std::string makeName(const std::string& name, const bls::Id& id)
{
	const std::string suf = ".txt";
	if (id.isZero()) return name + suf;
	std::ostringstream os;
	os << name << id << suf;
	return os.str();
}

template<class T>
void save(const std::string& file, const T& t, const bls::Id& id = 0)
{
	const std::string name = makeName(file, id);
	std::ofstream ofs(name.c_str(), std::ios::binary);
	if (!(ofs << t)) {
		throw cybozu::Exception("can't save") << name;
	}
}

template<class T>
void load(T& t, const std::string& file, const bls::Id& id = 0)
{
	const std::string name = makeName(file, id);
	std::ifstream ifs(name.c_str(), std::ios::binary);
	if (!(ifs >> t)) {
		throw cybozu::Exception("can't load") << name;
	}
}

int init()
{
	printf("make %s and %s files\n", secFile.c_str(), pubFile.c_str());
	bls::SecretKey sec;
	sec.init();
	save(secFile, sec);
	bls::PublicKey pub;
	sec.getPublicKey(pub);
	save(pubFile, pub);
	return 0;
}

int sign(const std::string& m, int id)
{
	printf("sign message `%s` by id=%d\n", m.c_str(), id);
	bls::SecretKey sec;
	load(sec, secFile, id);
	bls::Sign s;
	sec.sign(s, m);
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
	bls::SecretKey sec;
	load(sec, secFile);
	bls::SecretKeyVec msk;
	sec.getMasterSecretKey(msk, k);
	std::vector<bls::SecretKey> secVec(n);
	for (int i = 0; i < n; i++) {
		secVec[i].set(msk, i + 1);
	}
	for (int i = 0; i < n; i++) {
		const bls::Id& id = secVec[i].getId();
		save(secFile, secVec[i], id);
		bls::PublicKey pub;
		secVec[i].getPublicKey(pub);
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
	opt.appendOpt(&id, 0, "id", ": id of secretKey");
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
