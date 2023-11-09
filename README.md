# SBOM-Homework
<p>
  This project takes a directory with many software projects and retuns a sbom (Software Bill of Material) for all of them. The input required is the sbom.py file and a path to the directory with the software projects. <br>
  I have made a very simple test directory that has 2 folders, one with requirement.txt and the other with package.json and package-lock.json. This is done because I need to have something to test my homework with. As a recommendation you should give a path to another directory to test the SBOM properly
</p>
<h2>Requirements</h2>
<p>Needs Python3 and git (to clone this project)</p>
<h2>How to run the project</h2>
<p>
  Once the project is cloned, just write this in the terminal: <br>
  <li>python3 sbom.py 'path to directory'</li><br>
  If that for some reason does not work try with 'python' instead of 'python3'
</p>
<h2>Known issues / bugs</h2>
<p>I have not found any</p>
<h2>Ideas for features</h2>
<li>Dependency analysis. A analytic tool that helps identify vulnerable or outdated components and provides a recommendation to update the component</li>
<li>Version history. This would enable you to keep track of component versions and easly monitor updates and changes to software components</li>
<li>Tracking change to the SBOM. Keeping a record of changes to the SBOM for the last number of changes.</li>
