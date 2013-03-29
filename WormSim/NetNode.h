#ifndef _NETNODE_H
#define _NETNODE_H

#include <yaml-cpp\yaml.h>

#include <boost\graph\undirected_graph.hpp>
#include <boost\asio\ip\address.hpp>
#include <map>

#define uint unsigned int

using namespace std;

typedef boost::undirected_graph<> Graph;

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

typedef vector<Vulnerability*> VulnVect;
typedef vector<Vulnerability*>::iterator VulnVectIter;

class NodeType
{
public:
	NodeType();
	NodeType(string ID, string desc);
	void operator << (const YAML::Node& node);
	VulnVect& getVulnVector();
	string& getID();
	string& getDesc();
	bool addVuln(Vulnerability* toAdd);
	bool removeVuln(Vulnerability* toRem);
	void addVulns(VulnVect& toAdd);
	void removeVulns(VulnVect& toRem);
private:
	string nodeID;
	string desc;
	VulnVect vulnVector;
	vector<string> vulnsToAdd; //Can't store references as they might be destroyed when the YAML::Node disappears.
};

class Gateway
{
public:
	Gateway();
	Gateway(string ID, string desc);
private:
	bool generateSubGraph();
	string gateID;
	string desc;
	string ipAddr; //String representation of IP, could be a range or what have you, need to build a utility for dealing with this
	vector<NodeType*> nodeTypes;
	Graph gatewayGraph; //Node infectiong raph.
	
};

#endif