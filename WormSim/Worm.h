//Worm.h defines template for worm configuration
#ifndef _WORM_H
#define _WORM_H

#include <yaml-cpp\yaml.h>

#define WORM_CONFIG_PATH "worm.yml"

class Worm
{
public:
	Worm();
	Worm(const Worm& rhs);
	Worm& operator=(const Worm& rhs);
private:

};

#endif