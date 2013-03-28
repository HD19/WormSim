#ifndef _NETNODE_H
#define _NETNODE_H

#include <yaml-cpp\yaml.h>
#include <map>

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
	NodeDescriptor(string ID, string desc);
	void operator << (const YAML::Node& node);
	uint GetVulnVector();
	string& getID();
	void addVuln(Vulnerability* toAdd);
	void removeVuln(Vulnerability* toRemove);
private:
	string nodeID;
	string description;
	map<string, Vulnerability*> vulnMap;
	map<string, NodeDescriptor*> nodeTypeMap;
};

class Gateway
{
public:
	Gateway();
private:
	string gateID;
};

#endif