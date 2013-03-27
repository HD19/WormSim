#include "NetNode.h"

Vulnerability::Vulnerability()
{

}

Vulnerability::Vulnerability(string identifier, string description): vulnID(identifier), desc(description)
{

}

void Vulnerability::operator >> (const YAML::Node& node, Vulnerability& rhs)
{
	try
	{
		node["ID"] >> rhs.vulnID;
		node["Desc"] >> rhs.desc;
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

