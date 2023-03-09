/**
 *  Copyright 2023 Thomas "twevs" Evans
 *
 *  This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
 *  License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any
 *  later version.
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 *  warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 *  details.
 *
 *  You should have received a copy of the GNU General Public License along with this program. If not, see
 *  <https://www.gnu.org/licenses/>. 
 */

package highpcodeviewer;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = PluginCategoryNames.MISC,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "High P-Code Viewer",
	description = "Adds a window that shows the high P-code for the current function."
)
//@formatter:on
public class HighPCodeViewerPlugin extends ProgramPlugin {

	HighPCodeViewerProvider provider;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public HighPCodeViewerPlugin(PluginTool tool) {
		super(tool);

		provider = new HighPCodeViewerProvider(tool, getName());
	}
	
	@Override
	protected void programDeactivated(Program program)
	{
		provider.clear();
	}
	
	@Override
	protected void locationChanged(ProgramLocation loc)
	{
		provider.locationChanged(currentProgram, loc);
	}
}
