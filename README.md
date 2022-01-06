# linux_tag_to_android
A version of linux tag and add some change to let android can work

初始化本地仓库  
git init 


用命令git commit告诉Git，把文件提交到仓库。引号内为提交注释  
git commit -m 'xxx'


关联到远程库  
git remote add origin 你的远程库地址


把本地库的内容推送到远程  
git push -u origin master


把git上远程库的代码克隆到本地并运行  
git clone +'远程仓库的ssh或者https地址'

**撤销某笔提交**  
1.git reset HEAD^  
  HEAD^上一个版本 

2.git checkout filename   
  --soft //撤销commit 不撤销git add   
  --hard //撤销commot 撤销git add    
     
3.git push origin -f  
  撤销掉远端的提交   
  
**保存本地修改到git栈**
1. git stash  
   保存修改  
   
2. git pull  
   更新代码  

3. git stash pop  
   修改合并到代码中
  

 

