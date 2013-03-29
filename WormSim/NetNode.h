#ifndef _NETNODE_H
#define _NETNODE_H

#include <yaml-cpp\yaml.h>

#include <boost\graph\undirected_graph.hpp>
#include <map>

#define uint unsigned int

using namespace std;

typedef boost::undirected_graph<> Graph;

enum class GraphDist { Random, Range, Count, Routes };

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

typedef vector<NodeType*> NTVect;
typedef vector<NodeType*>::iterator NTVectIter;

class Gateway
{
public:
	Gateway();
	Gateway(string ID, string addr, string desc);
	void operator << (const YAML::Node& node);
private:
	bool generateSubGraph(); // Will generate a graph based on the given configuration and distribution.
	bool generateSubGraph(map<string, int>& nodeMap);
	bool generateSubGraph(map<string, vector<string>>& nodeMap);
	GraphDist subGraphDist;
	string gateID;
	string desc;
	string ipAddr; //String representation of IP, could be a range or what have you, need to build a utility for dealing with this
	NTVect nodeTypes;
	vector<string> nodeTypesToAdd;	//Store node types that need to be linked up. They should be in the NetMap's map later.
	Graph gatewayGraph; //Node infectiong raph.
	

};
#endif