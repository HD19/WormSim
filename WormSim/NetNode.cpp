#include "NetNode.h"

Vulnerability::Vulnerability()
{

}

Vulnerability::Vulnerability(string identifier, string description): vulnID(identifier), desc(description)
{

}

const string& Vulnerability::getID()
{
	return this->vulnID;
}

const string& Vulnerability::getDesc()
{
	return this->desc;
}

void Vulnerability::operator << (const YAML::Node& node)
{
	try
	{
		node["ID"] >> this->vulnID;
		node["Desc"] >> this->desc;
	}
	catch(exception& ex)
	{
		cout << "[-] Failed to read Vulnerability node:" << endl << ex.what() << endl;
		return;
	}
}

NodeDescriptor::NodeDescriptor()
{
	return;
}

NodeDescriptor::NodeDescriptor(string ID, string desc): nodeID(ID), description(desc)
{
	return;
}

void NodeDescriptor::operator<<(const YAML::Node& node)
{
	//Look at the spec and fill in the appropriate variables

}
