/*
* lbc.c
* big-number library for Lua 5.1 based on GNU bc-1.06 core library
* Luiz Henrique de Figueiredo <lhf@tecgraf.puc-rio.br>
* 04 Apr 2010 22:40:22
* This code is hereby placed in the public domain.
*/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "bconfig.h"
#include "number.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#define lua_boxpointer(L,u) \
	(*(void **)(lua_newuserdata(L, sizeof(void *))) = (u))

#define MYNAME		"bc"
#define MYVERSION	MYNAME " library for " LUA_VERSION " / Apr 2010 / "\
			"based on GNU bc-1.06"
#define MYTYPE		MYNAME " bignumber"

static int DIGITS=0;
static lua_State *LL=NULL;

void bc_error(const char *mesg)
{
 luaL_error(LL,"(bc) %s",mesg ? mesg : "not enough memory");
}

void Bnew(lua_State *L, bc_num x)
{
 lua_boxpointer(L,x);
 luaL_getmetatable(L,MYTYPE);
 lua_setmetatable(L,-2);
}

bc_num Bget(lua_State *L, int i)
{
 LL=L;
 switch (lua_type(L,i))
 {
  case LUA_TNUMBER:
  case LUA_TSTRING:
  {
   bc_num x=NULL;
   const char *s=lua_tostring(L,i);
   for (; isspace(*s); s++);		/* bc_str2num chokes on spaces */
   bc_str2num(&x,(char*)s,DIGITS);
   if (bc_is_zero(x))			/* bc_str2num chokes on sci notation */
   {
	char *t=strchr(s,'e');
	if (t==NULL) t=strchr(s,'E');
	if (t!=NULL)
	{
		bc_num y=NULL,n=NULL;
		int c=*t; *t=0;		/* harmless const violation! */
		bc_str2num(&x,(char*)s,DIGITS);
		*t=c;
		bc_int2num(&y,10);
		bc_int2num(&n,atoi(t+1));
		bc_raise(y,n,&y,DIGITS);
		bc_multiply(x,y,&x,DIGITS);
		bc_free_num(&y);
		bc_free_num(&n);
	}
   }
   Bnew(L,x);
   lua_replace(L,i);
   return x;
  }
  default:
   return *((void**)luaL_checkudata(L,i,MYTYPE));
 }
 return NULL;
}

static int Bdo1(lua_State *L, void (*f)(bc_num a, bc_num b, bc_num *c, int n))
{
 bc_num a=Bget(L,1);
 bc_num b=Bget(L,2);
 bc_num c=NULL;
 f(a,b,&c,DIGITS);
 Bnew(L,c);
 return 1;
}

static int Bdigits(lua_State *L)		/** digits([n]) */
{
 lua_pushinteger(L,DIGITS);
 DIGITS=luaL_optint(L,1,DIGITS);
 return 1;
}

static int Btostring(lua_State *L)		/** tostring(x) */
{
 bc_num a=Bget(L,1);
#if 0
 if (lua_toboolean(L,2))
 {
  lua_pushlstring(L,a->n_value,a->n_len+a->n_scale);
  lua_pushinteger(L,a->n_len);
  return 2;
 }
 else
#endif
 {
  char *s=bc_num2str(a);
  lua_pushstring(L,s);
  free(s);
  return 1;
 }
}

static int Btonumber(lua_State *L)		/** tonumber(x) */
{
 Btostring(L);
 lua_pushnumber(L,lua_tonumber(L,-1));
 return 1;
}

static int Biszero(lua_State *L)		/** iszero(x) */
{
 bc_num a=Bget(L,1);
 lua_pushboolean(L,bc_is_zero(a));
 return 1;
}

static int Bisneg(lua_State *L)			/** isneg(x) */
{
 bc_num a=Bget(L,1);
 lua_pushboolean(L,bc_is_neg(a));
 return 1;
}

static int Bnumber(lua_State *L)		/** number(x) */
{
 Bget(L,1);
 lua_settop(L,1);
 return 1;
}

static int Bcompare(lua_State *L)		/** compare(x,y) */
{
 bc_num a=Bget(L,1);
 bc_num b=Bget(L,2);
 lua_pushinteger(L,bc_compare(a,b));
 return 1;
}

static int Beq(lua_State *L)
{
 bc_num a=Bget(L,1);
 bc_num b=Bget(L,2);
 lua_pushboolean(L,bc_compare(a,b)==0);
 return 1;
}

static int Blt(lua_State *L)
{
 bc_num a=Bget(L,1);
 bc_num b=Bget(L,2);
 lua_pushboolean(L,bc_compare(a,b)<0);
 return 1;
}

static int Badd(lua_State *L)			/** add(x,y) */
{
 return Bdo1(L,bc_add);
}

static int Bsub(lua_State *L)			/** sub(x,y) */
{
 return Bdo1(L,bc_sub);
}

static int Bmul(lua_State *L)			/** mul(x,y) */
{
 return Bdo1(L,bc_multiply);
}

static int Bpow(lua_State *L)			/** pow(x,y) */
{
 return Bdo1(L,bc_raise);
}

static int Bdiv(lua_State *L)			/** div(x,y) */
{
 bc_num a=Bget(L,1);
 bc_num b=Bget(L,2);
 bc_num c=NULL;
 if (bc_divide(a,b,&c,DIGITS)!=0) return 0;
 Bnew(L,c);
 return 1;
}

static int Bmod(lua_State *L)			/** mod(x,y) */
{
 bc_num a=Bget(L,1);
 bc_num b=Bget(L,2);
 bc_num c=NULL;
 if (bc_modulo(a,b,&c,0)!=0) return 0;
 Bnew(L,c);
 return 1;
}

static int Bdivmod(lua_State *L)		/** divmod(x,y) */
{
 bc_num a=Bget(L,1);
 bc_num b=Bget(L,2);
 bc_num q=NULL;
 bc_num r=NULL;
 if (bc_divmod(a,b,&q,&r,0)!=0) return 0;
 Bnew(L,q);
 Bnew(L,r);
 return 2;
}

static int Bgc(lua_State *L)
{
 bc_num x=Bget(L,1);
 bc_free_num(&x);
 lua_pushnil(L);
 lua_setmetatable(L,1);
 return 0;
}

static int Bneg(lua_State *L)			/** neg(x) */
{
 bc_num a=bc_zero;
 bc_num b=Bget(L,1);
 bc_num c=NULL;
 bc_sub(a,b,&c,DIGITS);
 Bnew(L,c);
 return 1;
}

static int Btrunc(lua_State *L)			/** trunc(x,[n]) */
{
 bc_num a=Bget(L,1);
 bc_num c=NULL;
 bc_divide(a,bc_one,&c,luaL_optint(L,2,0));
 Bnew(L,c);
 return 1;
}

static int Bpowmod(lua_State *L)		/** powmod(x,y,m) */
{
 bc_num a=Bget(L,1);
 bc_num k=Bget(L,2);
 bc_num m=Bget(L,3);
 bc_num c=NULL;
 if (bc_raisemod(a,k,m,&c,0)!=0) return 0;
 Bnew(L,c);
 return 1;
}

static int Bsqrt(lua_State *L)			/** sqrt(x) */
{
 bc_num a=Bget(L,1);
 bc_num b=bc_zero;
 bc_num c=NULL;
 bc_add(a,b,&c,DIGITS);				/* bc_sqrt works inplace! */
 if (bc_sqrt(&c,DIGITS)==0) return 0;
 Bnew(L,c);
 return 1;
}

static const luaL_Reg R[] =
{
	{ "__add",	Badd	},		/** __add(x,y) */
	{ "__div",	Bdiv	},		/** __div(x,y) */
	{ "__eq",	Beq	},		/** __eq(x,y) */
	{ "__gc",	Bgc	},
	{ "__lt",	Blt	},		/** __lt(x,y) */
	{ "__mod",	Bmod	},		/** __mod(x,y) */
	{ "__mul",	Bmul	},		/** __mul(x,y) */
	{ "__pow",	Bpow	},		/** __pow(x,y) */
	{ "__sub",	Bsub	},		/** __sub(x,y) */
	{ "__tostring",	Btostring},		/** __tostring(x) */
	{ "__unm",	Bneg	},		/** __unm(x) */
	{ "add",	Badd	},
	{ "compare",	Bcompare},
	{ "digits",	Bdigits	},
	{ "div",	Bdiv	},
	{ "divmod",	Bdivmod	},
	{ "isneg",	Bisneg	},
	{ "iszero",	Biszero	},
	{ "mod",	Bmod	},
	{ "mul",	Bmul	},
	{ "neg",	Bneg	},
	{ "number",	Bnumber	},
	{ "pow",	Bpow	},
	{ "powmod",	Bpowmod	},
	{ "sqrt",	Bsqrt	},
	{ "sub",	Bsub	},
	{ "tonumber",	Btonumber},
	{ "tostring",	Btostring},
	{ "trunc",	Btrunc	},
	{ NULL,		NULL	}
};

LUALIB_API int luaopen_bc(lua_State *L)
{
 bc_init_numbers();
 luaL_newmetatable(L,MYTYPE);
 lua_setglobal(L,MYNAME);
 luaL_register(L,MYNAME,R);
 lua_pushliteral(L,"version");			/** version */
 lua_pushliteral(L,MYVERSION);
 lua_settable(L,-3);
 lua_pushliteral(L,"__index");
 lua_pushvalue(L,-2);
 lua_settable(L,-3);
 return 1;
}
