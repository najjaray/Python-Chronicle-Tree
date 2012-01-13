
#	====================================================================================
#	Project Name:		Chronicle Tree
#	Project Purpose:	Education
#	Project Supervisor:	Greg Benson, USF Professor 
#	Participants:		Ali Alnajjar USF MS Web Science Student
#	Contact:			najjaray@gmail.com
#	====================================================================================


# sa.py - state recording and analysis

import sys
import stackless
import pickle
import inspect
import shlex
import dis
import byteplay 
import opcode
import sqlite3 # to save the data in sqlite3 database
from objdump import objdump
from multiprocessing import Process

# Configuration

# If fold_lines is True we record a single state for each line executed,
# not each bytecode.
fold_lines = False

# record_modules lists the modules for which we want to record execution.
record_modules = ['__main__']

# Notes
# - Only supports single-threaded applications.
#   - To handle multiple threads we need to modifiy the thread module
	
def SA_ROOT(filename):
	"""Root function for tasket container"""
	# Setup fake global name space
	sa_root_globals = {}
	sa_root_globals['__builtins__'] = globals()['__builtins__']
	sa_root_globals['__name__'] = '__main__'
	sa_root_globals['__doc__'] = None
	sa_root_globals['__package__'] = None
	print '[state] root begin'
	# Ensure that program appears to be running at the top level namespace.
	execfile(filename, sa_root_globals, sa_root_globals)
	print '[state] root end'
	
class SA_Control(object):
	"""State Analysis Control Container"""
	ObjList = []
	ObjRObj = []
	StatesList = []
	def __init__(self):
		self.state_count = 0
		self.state_skips = 0
		pass
		
	def start(self, filename):
		self.filename = filename
		self.states = []
		self.state_count = 0
		self.state_skips = 0
		self.task = stackless.tasklet( SA_ROOT )(self.filename)
		
	def load(self, DBName,index=0): ### Added in project 3
		conn = sqlite3.connect(DBName)
		c = conn.cursor()
		c.execute('''select state from states where id ==%d''' % (index))
		ttask = c.fetchone()
		self.task = pickle.loads(ttask[0])
		self.task.insert()
		self.state_count = index
		conn.close()
			
	def end(self):
		print '[state] state count = %d' % (self.state_count)
		print '[state] state skips = %d' % (self.state_skips)
		del self.task

	def step(self, count=1):
		self.task.insert()
		self.task = stackless.run(count)
		return self.task

	def run(self, record=False):
		prev_lineno = 0;
		if record:
			self.CreateDB(sfilename)
		while self.step(1):

			# Skip SA_ROOT
			if self.task.frame.f_code.co_name == "SA_ROOT":
				continue
				
			# Skip modules
			if self.task.frame.f_globals['__name__'] not in record_modules:
				continue

			# Fold lines
			if fold_lines:
				if self.task.frame.f_lineno == prev_lineno:
					continue
				else:
					prev_lineno = self.task.frame.f_lineno

			if record:
				try:
					state = pickle.dumps(self.task, 2)
					#	self.states.append(state)
				except:
					self.state_skips += 1
				p = Process(target=self.SaveState, args=(sfilename,self.state_count,state,))
				p.start()
				p.join()
			self.state_count += 1

	def SaveState(self, DBName, sid, arg): ### Added in project 3
		conn = sqlite3.connect(DBName)
		c = conn.cursor()
		c.execute('insert into states(Id,state) values(?,?)' , (sid,sqlite3.Binary(arg)))
		conn.commit()
		conn.close()

	def examine(self, sid, ex_code):
		str_ex_code =''
		ex_code = ex_code.strip()
		ex_code_array = ex_code.split()
		new_ex_code=[]
		for i,expr in enumerate(ex_code_array):
			if len(expr)>5:
				if(expr.find("function")<>-1):
					function = self.task.frame.f_code.co_name
					result = eval(expr)
					#print 'ex_code_array(%d) = %s is %s' % (i,expr,result)
					new_ex_code.insert(i,result)
				elif (expr.find("method")<>-1):
					method = self.task.frame.f_globals['__name__']
					result = eval(expr)
					new_ex_code.insert(i,result)
				elif (expr.find("module")<>-1):
					module = self.task.frame.f_code.co_filename
					result = eval(expr)
					new_ex_code.insert(i,result)
				elif (expr.find("class")<>-1):
					#module = self.task.frame.f_code.co_filename
					#result = eval(expr)
					new_ex_code.insert(i,'True')
			else:
				new_ex_code.insert(i,expr)
			
		for expr in new_ex_code:
			str_ex_code = str_ex_code +' '+ str(expr)
		str_ex_code = str_ex_code.strip()
		try:
			rv = eval(str_ex_code, self.task.frame.f_globals, self.task.frame.f_locals)
			if rv == True:
				print "The expression [%s] is ture in state (%d)" % (ex_code,sid)
				#print "The expression [%s] is ture in state (%d) line (%d)" % (ex_code,sid,self.task.frame.f_lineno)
		except:
			rv = None
		
	def examine_all(self,DBName, ex_code,index=0):
		print'[examin all]'
		conn = sqlite3.connect(DBName)
		c = conn.cursor()
		c.execute('''select * from states where Id >=%d''' % index)
		for state in c:
			self.task = pickle.loads(state[1])
			self.examine(state[0],ex_code)
			#rv = self.examine(ex_code)
			#print rv
		conn.close()
	
	def GetSourseof(self,index):
		f = open(self.task.frame.f_code.co_filename, 'r')
		fcounter = 0 
		while fcounter<self.task.frame.f_lineno:
			Code = f.readline()
			fcounter +=1
		f.close() 
		return Code.strip()
				
	def GetHistory2(self,DBName, Obj,index=0):
		print'[History] of %s' % (Obj)
		conn = sqlite3.connect(DBName)
		c = conn.cursor()
		c.execute('''select * from states where Id =%d  order by Id''' % index)
		OOb = None
		Created = False
		for state in c:
			self.task = pickle.loads(state[1])
			c= byteplay.Code.from_code(self.task.frame.f_code)
			print c.code
		print "ccc"
		
							
	def GetBytecode(self,code, lino):
		LineBytecode = []
		c= byteplay.Code.from_code(code)
		n = len(c.code)
		i = 0
		while i<n:
			if str(c.code[i][0]) in 'SetLineno':
				CurLineNo = c.code[i][1]
			if (CurLineNo == lino):
				LineBytecode.append(c.code[i])
				#print CurLineNo
			i=i+1
		return LineBytecode
		
	def GetObjects(self,Bytecode):
		objectList = []
		for i in Bytecode:
			if str(i[0])== 'LOAD_NAME':
				objectList.append(i[1])
		return objectList
					 
	def GetConst(self,Bytecode):
		objectList = []
		for i in Bytecode:
			if str(i[0])== 'LOAD_CONST':
				if str(i[1]) != 'None':
					objectList.append(i[1])

		return objectList
	
	def GetHistory(self,DBName, Obj,index=-1,In=''):
	#	print H + Obj + ' ',
		LMd = -1
		Cont = False
		#print "%s [History] %s " % (H,Obj)
		conn = sqlite3.connect(DBName)
		c = conn.cursor()
		CurBytecode = []
		ProObjList = []
		ProConsList = []
		if index == -1:
			c.execute('''select * from states order by Id''')
		else:
			c.execute('''select * from states where Id <=%d  order by Id''' % index)
		OOid = None
		OOiv = None
		Created = False
		for stateno,state in enumerate(c):
			self.task = pickle.loads(state[1])
			if eval( "'" + Obj + "' in self.task.frame.f_locals"):
				if Created:
					if eval("id("+Obj+")",self.task.frame.f_globals,self.task.frame.f_locals) != OOid and self.task.frame.f_locals[Obj]!= OOiv:
						OOid = eval("id("+Obj+")",self.task.frame.f_globals,self.task.frame.f_locals)
						OOiv = self.task.frame.f_locals[Obj]
						# Save the state number in the last modify state to return it
						LMd = state[0]
						if (state[0],Obj,self.task.frame.f_locals[Obj],self.GetSourseof(self.task.frame.f_lineno)) not in self.ObjList:
							self.ObjList.append((state[0],Obj,self.task.frame.f_locals[Obj],self.GetSourseof(self.task.frame.f_lineno)))
							# if the state number was not added to states list ---> add it
							if state[0] not in self.StatesList:
								self.StatesList.append(state[0])
						# Getting the current bytecode, object list, constant list
						CurBytecode = self.GetBytecode(self.task.frame.f_code,self.task.frame.f_lineno)
						ProObjList =  self.GetObjects(CurBytecode)			
						ProConsList = self.GetConst(CurBytecode)
						#if the object list is not empty
						if len(ProObjList)>0:
							# loop to handle all objects is the list
							for Lobj in ProObjList:
								if Obj == Lobj:
									LastM = self.GetHistory(DBName, Lobj,state[0]-1,In+'     ')
								else:
									LastM = self.GetHistory(DBName, Lobj,state[0],In+'     ')
								# link the parent object with the new object last modifed
								if (state[0],Obj,LastM,Lobj) not in self.ObjRObj:
									self.ObjRObj.append((state[0],Obj,LastM,Lobj))
									
						if len(ProConsList)>0:
							for Lcon in ProConsList:
								if (state[0],Lcon,'','%s' % 'cons.') not in self.ObjList:
									self.ObjList.append((state[0],Lcon,'','%s' % 'cons.'))
									if state[0] not in self.StatesList:
										self.StatesList.append(state[0])
								if (state[0],Obj,state[0],Lcon) not in self.ObjRObj:
									self.ObjRObj.append((state[0],Obj,state[0],Lcon)
									if state[0] not in self.StatesList:
										self.StatesList.append(state[0])
				else:
					Created = True
					LMd = state[0]
					if (state[0],Obj,self.task.frame.f_locals[Obj],self.GetSourseof(self.task.frame.f_lineno)) not in self.ObjList:
						self.ObjList.append((state[0],Obj,self.task.frame.f_locals[Obj],self.GetSourseof(self.task.frame.f_lineno)))						
					OOid = eval("id("+Obj+")",self.task.frame.f_globals,self.task.frame.f_locals)
					OOiv = self.task.frame.f_locals[Obj]
					CurBytecode = self.GetBytecode(self.task.frame.f_code,self.task.frame.f_lineno)
					ProObjList =  self.GetObjects(CurBytecode)			
					ProConsList = self.GetConst(CurBytecode)

					if len(ProObjList)>0:
						for Lobj in ProObjList:
							if state[0] not in self.StatesList:
								self.StatesList.append(state[0])
							if Obj == Lobj:
								LastM = self.GetHistory(DBName, Lobj,state[0]-1,In+'     ')
							else:
								LastM = self.GetHistory(DBName, Lobj,state[0],In+'     ')
							# link the parent object with the new object last modifed
							if (state[0],Obj,LastM,Lobj) not in self.ObjRObj:
								self.ObjRObj.append((state[0],Obj,LastM,Lobj))
					if len(ProConsList)>0:
						for Lcon in ProConsList:
							if (state[0],Lcon,'','%s' % 'cons.') not in self.ObjList:
								self.ObjList.append((state[0],Lcon,'','%s' % 'cons.'))
								if state[0] not in self.StatesList:
									self.StatesList.append(state[0])
							if (state[0],Obj,state[0],Lcon) not in self.ObjRObj:
								self.ObjRObj.append((state[0],Obj,state[0],Lcon))
								if state[0] not in self.StatesList:
									self.StatesList.append(state[0])
		if Created == False:
			print "The Object [%s] does not exist" % Obj
		conn.close()
		return LMd
			
	def DrawGraph(self):
		print "Generating Graph"
		from time import gmtime, strftime
		DotFilename = strftime("%Y%m%d%H%M%S", gmtime())
		self.StatesList.sort()
		#print DotFilename
		f = open(DotFilename+".dot", 'w')
		f.write("digraph asde91 { \n")
		f.write("ranksep=.75; size = \"7.5,7.5\";\n{\n")  
		f.write("node [shape=plaintext, fontsize=16];\n") 
		f.write("/* the time-line graph */\n")
		
		# states timeline 
		
		for i,state in enumerate(self.StatesList):
			if i != 0:
				f.write(" -> ")
			f.write("\"State %s\"" %str(state))
		f.write(";\n")
		f.write("node [shape=record];\n")
		nodes = []
		for stateNo in (self.StatesList):
			f.write("{ rank = same; \"State %d\";" % stateNo)
			# objects cons. and functions
			funclino = -1
			for obj in self.ObjList:
				if obj[0] == stateNo:
					if obj[2] == '':
						if obj[1] != -1 and obj[0]!= funclino:
							f.write(" \"%s%s\" [label =\"%s | %s\"]; " % (obj[0],obj[1],obj[1],obj[3]))
							nodes.append((obj[0],obj[1]))
					else:
						f.write(" \"%s%s\" [label =\"%s (%s)| %s\"]; " % (obj[0],obj[1],obj[1],obj[2],obj[3]))
						nodes.append((obj[0],obj[1]))
						if obj[3].find('import') != -1:
							funclino = obj[0]
			f.write(" }\n")
			
			# relationships (connections)
			
		for rel in self.ObjRObj:
			fromS = rel[0]
			fromO = rel[1]
			toS =  rel[2]
			toO = rel[3]
			if (toS,toO) in nodes:
				f.write("\"%s%s\" -> \"%s%s\";\n" %(toS,toO,fromS,fromO))
		f.write("}\n")
		f.write("}\n")
		f.close()
		import os
		os.system("dot -Tps " + DotFilename + ".dot -o " + DotFilename + ".ps ")
		print "Graph " + DotFilename +".ps Generated"
		os.system("open " + DotFilename + ".ps")
		
	def CreateDB(self, DBName):
		conn = sqlite3.connect(DBName)
		c = conn.cursor()
		c.execute('''create table states (Id int, state BLOB )''')
		conn.commit()
		conn.close()
		
	def info(self, DBName):
		conn = sqlite3.connect(DBName)
		c = conn.cursor()
		c.execute('''select count(*) from states''')
		print '[state] Database Name = %s' % (DBName)
		print '[stare] state count = %d' % (c.fetchone())
		conn.close()

	def DBC(self, DBName):
		conn = sqlite3.connect(DBName)
		c = conn.cursor()
		c.execute('''select * from states''')
		print "=====|====---..."
		for state in c:
			print "%d - " % (state[0])
		print "=====|====---..."
		conn.close()
			
if __name__ == '__main__':
	if len(sys.argv) == 1:
		print 'usage: sa.py command args'
		print 'command:'
		print '  run <prog.py> <args>'
		print '  record <statefile> <prog.py> <args>'
		print '  play <statefile> [<index|range>]'
		print '  info <statefile>'
		print '  examine <statefile> <index|range> <ex_code>'
		print '  examine_all <statefile> <ex_code>'
		sys.exit(1)
	argv_copy = sys.argv[:]
	
	cmd = sys.argv[1]
	
	if cmd == 'run':
		filename = sys.argv[2]
		sys.argv = sys.argv[2:]
		sa = SA_Control()
		sa.start(filename)
		sa.run()
		sa.end()
	elif cmd == 'record':
		sfilename = sys.argv[2]
		filename = sys.argv[3]
		sys.argv = sys.argv[3:]
		sa = SA_Control()
		sa.start(filename)
		sa.run(record=True)
		sa.end()
		#sa.save(sfilename)
	elif cmd == 'play':
		sfilename = sys.argv[2]
		sindex = int(sys.argv[3])
		sa = SA_Control()
		sa.load(sfilename, sindex)
		sa.run()
		sa.end()
	elif cmd == 'info':
		sfilename = sys.argv[2]
		sa = SA_Control()
		sa.load(sfilename)
		sa.info(sfilename)
	elif cmd == 'examine':
		sfilename = sys.argv[2]
		index = eval(sys.argv[3])
		#index = sys.argv[3]
		ex_code = sys.argv[4]
		sa = SA_Control()
		sa.load(sfilename, index)
		sa.examine_all(sfilename,ex_code,index)
	elif cmd == 'examine_all':
		sfilename = sys.argv[2]
		ex_code = sys.argv[3]
		sa = SA_Control()
		sa.load(sfilename)
		sa.examine_all(sfilename,ex_code)
	elif cmd == 'history':
		sfilename = sys.argv[2]
		Objecname = sys.argv[3]
		index = -1
		if len(sys.argv) == 5:
			index = int(sys.argv[4])
		sa = SA_Control()
		sa.load(sfilename)
		LastM = sa.GetHistory(sfilename,Objecname,index)
		#sa.ShowObj()
		#sa.ShowRelation()
		sa.DrawGraph()
#########
	elif cmd == 'test':
		sa = SA_Control()
		sfilename = sys.argv[2]
		sa.CreateDB(sfilename)
	elif cmd == 'DBC':
		sa = SA_Control()
		sfilename = sys.argv[2]
		sa.DBC(sfilename)
	else:
		print 'usage: sa.py command args'
		print 'command:'
		print '  run <prog.py> <args>'
		print '  record <statefile> <prog.py> <args>'
		print '  play <statefile> [<index|range>]'
		print '  info <statefile>'
		print '  examine <statefile> <index|range> <ex_code>'
		print '  examine_all <statefile> <ex_code>'
	
