#ifndef _NETNODE_H
#define _NETNODE_H

#include <yaml-cpp\yaml.h>

#define uint unsigned int


using namespace std;

class Vulnerability
{
public:
	Vulnerability();
	Vulnerability(string identifier, string description);
	void operator << (const YAML::Node& node);
	const string& getID();
	const string& getDesc();
private:
	string vulnID;
	string desc;
};

class NodeDescriptor
{
public:
	NodeDescriptor();
	NodeDescriptor(string desc, uint vulns);
	uint GetVulnVector();
	void setID();
	void addVuln(Vulnerability* toAdd);
	void removeVuln(Vulnerability* toRemove);
private:
	string nodeID;
	string description;
	vector<Vulnerability*> vulnVect;
};

class Gateway
{
public:
	Gateway();
private:
	string gateID;
};

#endif